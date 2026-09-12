//! The vault: seal state, the key hierarchy, and every operation on secrets.
//!
//! This is where the rules live. The HTTP layer above it only translates.
//!
//! Two invariants hold throughout:
//!
//! - Every change is written to the log before it is applied to memory, so
//!   what is in memory never runs ahead of what survived a crash.
//! - Nothing can be read while sealed. Not a secret, not a user, not a
//!   session: without the root key the log is opaque, so there is no state at
//!   all rather than state that happens not to be served.

use crate::barrier::Barrier;
use crate::validate;
use ls_core::crypto::aead::{Aad, DataKey};
use ls_core::crypto::{password, shamir, token};
use ls_core::random;
use ls_core::time::Timestamp;
use ls_store::{Event, Log, Sealed, State, StoreError, TokenKind};
use std::path::Path;
use zeroize::Zeroizing;

/// Length of the master key that the unseal shares reconstruct.
const MASTER_KEY_LEN: usize = 32;

/// Why an operation could not be carried out.
#[derive(Debug)]
pub enum VaultError {
    /// The vault is sealed. Nothing can be read or written.
    Sealed,
    /// The vault has already been initialised.
    AlreadyInitialized,
    /// The vault has not been initialised yet.
    NotInitialized,
    /// The shares did not reconstruct a key that opens the barrier.
    UnsealFailed,
    /// The store holds a barrier this build cannot read.
    UnreadableBarrier(&'static str),
    /// Initialisation wrote the barrier but could not finish. The store holds
    /// nothing yet, so the remedy is to remove it and start again.
    InitIncomplete,
    /// The share could not be read.
    BadShare,
    /// Wrong email or password. Deliberately one error for both.
    BadCredentials,
    /// The caller is not allowed to do this.
    Forbidden,
    /// Nothing of that name.
    NotFound(&'static str),
    /// Something of that name already exists.
    Conflict(&'static str),
    /// The request does not make sense.
    Invalid(&'static str),
    /// The value offered is larger than a secret may be.
    ValueTooLarge {
        /// Size offered.
        len: usize,
        /// Largest accepted.
        limit: usize,
    },
    /// A cryptographic operation failed.
    Crypto,
    /// The log failed.
    Store(StoreError),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sealed => f.write_str("the vault is sealed"),
            Self::AlreadyInitialized => f.write_str("already initialised"),
            Self::NotInitialized => f.write_str("not initialised"),
            Self::UnsealFailed => f.write_str("those shares do not open this vault"),
            Self::UnreadableBarrier(why) => {
                write!(f, "the store holds a barrier this build cannot read: {why}")
            }
            Self::InitIncomplete => f.write_str(
                "initialisation could not be completed; remove the data directory and run init again",
            ),
            Self::BadShare => f.write_str("that is not a valid unseal share"),
            Self::BadCredentials => f.write_str("wrong email or password"),
            Self::Forbidden => f.write_str("not allowed"),
            Self::NotFound(what) => write!(f, "no such {what}"),
            Self::Conflict(what) => write!(f, "that {what} already exists"),
            Self::Invalid(what) => write!(f, "invalid {what}"),
            Self::ValueTooLarge { len, limit } => {
                write!(f, "a secret value of {len} bytes exceeds the limit of {limit}")
            }
            Self::Crypto => f.write_str("a cryptographic operation failed"),
            Self::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<StoreError> for VaultError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// What `init` hands back, once, and never again.
#[derive(Debug)]
pub struct InitOutcome {
    /// The unseal shares, in printed form.
    pub shares: Vec<String>,
    /// The root token, able to create the first user.
    pub root_token: Zeroizing<String>,
    /// How many shares are needed to unseal.
    pub threshold: u8,
}

/// Progress through an unseal.
#[derive(Debug, Clone, Copy)]
pub struct UnsealStatus {
    /// Whether the vault is still sealed.
    pub sealed: bool,
    /// Distinct shares accepted so far.
    pub progress: usize,
    /// How many are needed.
    pub threshold: u8,
}

/// Who is making a request.
#[derive(Debug, Clone)]
pub struct Caller {
    /// The token used.
    pub token_id: String,
    /// What the token stands for.
    pub kind: TokenKind,
    /// The user, for a session.
    pub user_id: Option<String>,
    /// The project a machine token is confined to.
    pub project_id: Option<String>,
    /// The environment a machine token is confined to.
    pub environment_id: Option<String>,
}

impl Caller {
    /// How this caller appears in the audit trail.
    fn actor(&self) -> String {
        match (&self.user_id, self.kind) {
            (Some(user), _) => format!("user:{user}"),
            (None, TokenKind::Machine) => format!("machine:{}", self.token_id),
            (None, _) => format!("token:{}", self.token_id),
        }
    }
}

/// What an operation needs from the caller.
///
/// There are no roles in v1. What there is, is a small fixed answer to "what
/// is this token for", which is the difference between a leaked deploy token
/// reading one environment and a leaked deploy token owning the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Capability {
    /// Create the first account. The root token exists for this and nothing else.
    Bootstrap,
    /// Manage projects, environments, accounts, tokens, sealing and the audit trail.
    Administer,
    /// Read secret values.
    ReadSecrets,
    /// Write or delete secret values.
    WriteSecrets,
}

impl Capability {
    /// Whether a token of this kind carries this capability.
    const fn granted_to(self, kind: TokenKind) -> bool {
        match kind {
            // Spent on first use, and useless for anything else in the meantime.
            TokenKind::Root => matches!(self, Self::Bootstrap),
            // A person. No roles in v1, so a session can do everything.
            TokenKind::Session => true,
            // A machine reads the one environment it was issued for.
            TokenKind::Machine => matches!(self, Self::ReadSecrets),
        }
    }
}

/// A secret key and its plaintext value, on the way out to a caller.
pub type RevealedSecret = (String, Zeroizing<Vec<u8>>);

/// One entry of the audit trail.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// When it happened.
    pub at: Timestamp,
    /// Who did it.
    pub actor: String,
    /// What was attempted.
    pub action: String,
    /// What it was attempted on. Never a value.
    pub target: String,
    /// How it went.
    pub outcome: String,
}

/// The vault.
#[derive(Debug)]
pub struct Vault {
    log: Log,
    state: State,
    barrier: Option<Barrier>,
    root_key: Option<DataKey>,
    pending_shares: Vec<shamir::Share>,
}

impl Vault {
    /// Open the store at `path`, creating it if it is not there. The vault
    /// comes back sealed unless it has never been initialised.
    pub fn open(path: &Path) -> Result<Self, VaultError> {
        let mut log = Log::open(path)?;

        if log.repaired() {
            // Either a crash during a write, or someone editing the file. The
            // operator should know either way.
            ls_log::warn!(
                "the store had an incomplete record at the end, which was discarded",
                store = path.display()
            );
        }

        // Only barriers are stored in the clear, and re-splitting rewrites the
        // file rather than appending, so there is at most one. If it is there
        // and cannot be read, stop: reporting "not initialised" would let an
        // unauthenticated init lay a second key hierarchy over sealed data
        // that nothing could then open.
        let plain = log.read_plain()?;
        if plain.is_empty() && !log.is_empty() {
            // Records but no barrier: an init that failed partway, or a file
            // that has lost its head. Calling that "not initialised" would
            // invite a second init to lay a new key hierarchy over data the
            // new keys can never read.
            return Err(VaultError::UnreadableBarrier(
                "the store holds records but no barrier",
            ));
        }

        let barrier = match plain.last() {
            Some(payload) => {
                Some(Barrier::from_bytes(payload).map_err(VaultError::UnreadableBarrier)?)
            }
            None => None,
        };

        Ok(Self {
            log,
            state: State::default(),
            barrier,
            root_key: None,
            pending_shares: Vec::new(),
        })
    }

    /// Whether the root key is out of reach.
    pub fn is_sealed(&self) -> bool {
        self.root_key.is_none()
    }

    /// Whether the vault has ever been initialised.
    pub fn is_initialized(&self) -> bool {
        self.barrier.is_some()
    }

    /// How many shares an unseal needs, once initialised.
    pub fn threshold(&self) -> Option<u8> {
        self.barrier.as_ref().map(|b| b.threshold)
    }

    // --- seal and unseal ---------------------------------------------------

    /// Create the key hierarchy and leave the vault unsealed.
    pub fn init(&mut self, threshold: u8, shares: u8) -> Result<InitOutcome, VaultError> {
        if self.is_initialized() {
            return Err(VaultError::AlreadyInitialized);
        }

        let master_bytes =
            Zeroizing::new(random::bytes::<MASTER_KEY_LEN>().map_err(|_| VaultError::Crypto)?);
        let split = shamir::split(master_bytes.as_slice(), threshold, shares)
            .map_err(|_| VaultError::Invalid("share configuration"))?;

        let master_key = DataKey::from_bytes(master_bytes.as_slice()).ok_or(VaultError::Crypto)?;
        let root_key = DataKey::generate().map_err(|_| VaultError::Crypto)?;
        let wrapped = master_key
            .wrap(&root_key, &Barrier::context())
            .map_err(|_| VaultError::Crypto)?;

        // Everything that can fail happens before the first write. Otherwise a
        // failure here leaves a vault that is initialised but whose shares were
        // never handed back, and init refuses to run again.
        let issued = token::generate().map_err(|_| VaultError::Crypto)?;
        let token_id = new_id()?;

        let barrier = Barrier {
            threshold,
            shares,
            root_key: Sealed::from(wrapped),
            created_at: Timestamp::now(),
        };
        self.log.append_plain(&barrier.to_bytes())?;

        self.barrier = Some(barrier);
        self.root_key = Some(root_key);

        // The barrier is already on disk, so a failure here leaves a vault that
        // is initialised but has no way to create its first account. There is
        // nothing to lose at this point, so say plainly what to do about it.
        self.commit(Event::TokenIssued {
            id: token_id,
            token_hash: issued.hash().as_bytes().to_vec(),
            kind: TokenKind::Root,
            user_id: None,
            project_id: None,
            environment_id: None,
            label: Some("root".to_owned()),
            expires_at: None,
            created_at: Timestamp::now(),
        })
        .map_err(|_| VaultError::InitIncomplete)?;
        let root_token = issued.into_secret();

        Ok(InitOutcome {
            shares: split.iter().map(ToString::to_string).collect(),
            root_token,
            threshold,
        })
    }

    /// Split the master key again, into a fresh set of shares, and rotate the
    /// root key underneath them.
    ///
    /// The whole file is rewritten under a new root key and the old barrier
    /// stops existing. Superseding it would not have been enough: an
    /// append-only file keeps what it is given, so an old quorum would still
    /// open the vault from the same file, and cutting the file back to the old
    /// barrier would undo the re-split completely.
    ///
    /// Secret values keep their project data keys, which are simply re-wrapped,
    /// so nothing has to be decrypted and re-encrypted. The history and the
    /// audit trail are carried across.
    ///
    /// What this cannot do is reach copies of the file made earlier. Anyone
    /// holding a quorum of the old shares and an older copy can still open
    /// that copy. Re-splitting answers a lost share or a change of custodians;
    /// an exposed share needs a new vault and new values.
    pub fn rekey(
        &mut self,
        caller: &Caller,
        threshold: u8,
        shares: u8,
    ) -> Result<InitOutcome, VaultError> {
        self.require_unsealed()?;
        self.require(caller, Capability::Administer)?;

        let old_root = self.root_key.as_ref().ok_or(VaultError::Sealed)?;

        // Read the whole history back under the key that is going away.
        let mut events = Vec::new();
        for record in self.log.read_records(old_root)? {
            if record.sealed {
                events.push(Event::from_bytes(&record.payload)?);
            }
        }

        let new_root = DataKey::generate().map_err(|_| VaultError::Crypto)?;

        // Project data keys move across to the new root key. The keys
        // themselves do not change, so no stored value needs touching.
        let mut carried = Vec::with_capacity(events.len() + 1);
        for event in events {
            match event {
                Event::ProjectCreated {
                    id,
                    slug,
                    name,
                    data_key,
                    created_at,
                } => {
                    let context = project_key_context(&id);
                    let unwrapped = old_root
                        .unwrap_key(&(&data_key).into(), &context)
                        .map_err(|_| VaultError::Crypto)?;
                    let rewrapped = new_root
                        .wrap(&unwrapped, &context)
                        .map_err(|_| VaultError::Crypto)?;

                    carried.push(Event::ProjectCreated {
                        id,
                        slug,
                        name,
                        data_key: Sealed::from(rewrapped),
                        created_at,
                    });
                }
                other => carried.push(other),
            }
        }

        carried.push(Event::Audited {
            at: Timestamp::now(),
            actor: caller.actor(),
            action: "vault.rekey".to_owned(),
            target: "unseal shares".to_owned(),
            outcome: "ok".to_owned(),
        });

        let master_bytes =
            Zeroizing::new(random::bytes::<MASTER_KEY_LEN>().map_err(|_| VaultError::Crypto)?);
        let split = shamir::split(master_bytes.as_slice(), threshold, shares)
            .map_err(|_| VaultError::Invalid("share configuration"))?;
        let master_key = DataKey::from_bytes(master_bytes.as_slice()).ok_or(VaultError::Crypto)?;
        let wrapped_root = master_key
            .wrap(&new_root, &Barrier::context())
            .map_err(|_| VaultError::Crypto)?;

        let barrier = Barrier {
            threshold,
            shares,
            root_key: Sealed::from(wrapped_root),
            created_at: Timestamp::now(),
        };

        // One rewrite, through a temporary file and a rename, and the last
        // thing that can fail. Until it succeeds nothing has changed and the
        // old shares still work.
        let payloads: Vec<Vec<u8>> = carried.iter().map(Event::to_bytes).collect();
        self.log
            .compact(&new_root, &[barrier.to_bytes()], &payloads)?;

        let mut state = State::default();
        for event in carried {
            state.apply(event);
        }

        self.root_key = Some(new_root);
        self.barrier = Some(barrier);
        self.state = state;
        self.pending_shares.clear();

        Ok(InitOutcome {
            shares: split.iter().map(ToString::to_string).collect(),
            root_token: Zeroizing::new(String::new()),
            threshold,
        })
    }

    /// Offer one share towards an unseal.
    ///
    /// A share already offered does not count again, and a failed attempt
    /// clears the progress so the ceremony starts cleanly rather than mixing
    /// shares from two tries.
    pub fn submit_share(&mut self, printed: &str) -> Result<UnsealStatus, VaultError> {
        let barrier = self.barrier.as_ref().ok_or(VaultError::NotInitialized)?;
        let threshold = barrier.threshold;

        if !self.is_sealed() {
            return Ok(UnsealStatus {
                sealed: false,
                progress: 0,
                threshold,
            });
        }

        let share = shamir::Share::parse(printed).map_err(|_| VaultError::BadShare)?;

        // Offering the same share twice must not count twice. Comparing the
        // whole share rather than its index matters after a re-split, where
        // share 1 of the new set and share 1 of the old set are different
        // numbers that happen to share an index: dropping the second because
        // of that would make a valid share appear to do nothing.
        if !self.pending_shares.contains(&share) {
            self.pending_shares.push(share);
        }

        if self.pending_shares.len() < usize::from(threshold) {
            return Ok(UnsealStatus {
                sealed: true,
                progress: self.pending_shares.len(),
                threshold,
            });
        }

        match self.try_unseal() {
            Ok(()) => Ok(UnsealStatus {
                sealed: false,
                progress: 0,
                threshold,
            }),
            Err(error) => {
                self.pending_shares.clear();
                Err(error)
            }
        }
    }

    /// Throw away any shares offered so far.
    pub fn reset_unseal(&mut self) {
        self.pending_shares.clear();
    }

    /// Drop the root key, if the caller is allowed to.
    pub fn seal_as(&mut self, caller: &Caller) -> Result<(), VaultError> {
        self.require(caller, Capability::Administer)?;
        self.seal();
        Ok(())
    }

    /// Drop the root key. Everything becomes unreadable until unsealed again.
    pub fn seal(&mut self) {
        self.root_key = None;
        self.state = State::default();
        self.pending_shares.clear();
    }

    fn try_unseal(&mut self) -> Result<(), VaultError> {
        let barrier = self.barrier.as_ref().ok_or(VaultError::NotInitialized)?;

        let master_bytes =
            shamir::combine(&self.pending_shares).map_err(|_| VaultError::UnsealFailed)?;
        let master_key =
            DataKey::from_bytes(master_bytes.as_slice()).ok_or(VaultError::UnsealFailed)?;

        // If the shares were wrong, this is where it shows: the recombined key
        // fails to authenticate the wrapped root key.
        let root_key = master_key
            .unwrap_key(&(&barrier.root_key).into(), &Barrier::context())
            .map_err(|_| VaultError::UnsealFailed)?;

        let state = self.replay(&root_key)?;
        self.root_key = Some(root_key);
        self.state = state;
        self.pending_shares.clear();
        Ok(())
    }

    fn replay(&mut self, root_key: &DataKey) -> Result<State, VaultError> {
        let mut state = State::default();
        for record in self.log.read_records(root_key)? {
            if !record.sealed {
                continue; // the barrier
            }
            state.apply(Event::from_bytes(&record.payload)?);
        }
        Ok(state)
    }

    // --- users and tokens --------------------------------------------------

    /// Create a user account.
    ///
    /// The root token may do this once; using it spends it, so a copy left in
    /// terminal scrollback is not a permanent key to everything.
    pub fn create_user(
        &mut self,
        caller: &Caller,
        email: &str,
        password: &str,
    ) -> Result<String, VaultError> {
        self.require_unsealed()?;
        self.require(caller, Capability::Bootstrap)?;
        let email = validate::email(email)?;

        if self.state.user_by_email(&email).is_some() {
            return Err(VaultError::Conflict("user"));
        }

        let password_hash = password::hash(password).map_err(|error| match error {
            // Telling the caller their password is invalid when the machine
            // ran out of entropy sends them off fixing the wrong thing.
            password::PasswordError::Entropy => VaultError::Crypto,
            _ => VaultError::Invalid("password"),
        })?;
        let id = new_id()?;

        self.commit(Event::UserCreated {
            id: id.clone(),
            email,
            password_hash,
            created_at: Timestamp::now(),
        })?;

        Ok(id)
    }

    /// Exchange a password for a session token.
    pub fn login(
        &mut self,
        email: &str,
        password: &str,
        ttl_seconds: i64,
    ) -> Result<Zeroizing<String>, VaultError> {
        self.require_unsealed()?;
        check_lifetime(ttl_seconds)?;

        let normalised = validate::email(email).unwrap_or_default();
        let found = self.state.user_by_email(&normalised).cloned();

        let user = match found {
            Some(user) => user,
            None => {
                // Verify against a hash that cannot match, so an unknown
                // account costs the same as a wrong password and the timing
                // does not say which it was.
                password::verify(password, DUMMY_HASH);
                return Err(VaultError::BadCredentials);
            }
        };

        if !password::verify(password, &user.password_hash) {
            return Err(VaultError::BadCredentials);
        }

        self.issue_token(
            TokenKind::Session,
            Some(user.id),
            None,
            None,
            None,
            Some(ttl_seconds),
        )
    }

    /// Mint a token for a machine, confined to one environment.
    pub fn issue_machine_token(
        &mut self,
        caller: &Caller,
        project_slug: &str,
        environment_slug: &str,
        label: &str,
        ttl_seconds: Option<i64>,
    ) -> Result<Zeroizing<String>, VaultError> {
        self.require_unsealed()?;
        self.require(caller, Capability::Administer)?;
        if let Some(ttl) = ttl_seconds {
            check_lifetime(ttl)?;
        }
        let (project_id, environment_id) = self.resolve(project_slug, environment_slug)?;

        self.issue_token(
            TokenKind::Machine,
            None,
            Some(project_id),
            Some(environment_id),
            Some(label),
            ttl_seconds,
        )
    }

    /// Stop a token from working.
    ///
    /// Revoking your own token is always allowed, which is what logging out is.
    /// Revoking someone else's needs the run of the place.
    pub fn revoke_token(&mut self, caller: &Caller, id: &str) -> Result<(), VaultError> {
        self.require_unsealed()?;
        if id != caller.token_id {
            self.require(caller, Capability::Administer)?;
        }
        if self.state.token(id).is_none() {
            return Err(VaultError::NotFound("token"));
        }

        self.commit(Event::TokenRevoked {
            id: id.to_owned(),
            at: Timestamp::now(),
        })
    }

    /// Work out who a presented token belongs to. `None` if it is not usable,
    /// which includes the vault being sealed.
    pub fn authenticate(&self, presented: &str) -> Option<Caller> {
        if self.is_sealed() || presented.is_empty() {
            return None;
        }

        let hash = token::hash(presented);
        let found = self.state.token_by_hash(hash.as_bytes())?;
        if !found.is_valid_at(Timestamp::now()) {
            return None;
        }

        // The root token exists to create the first account, so the moment an
        // account exists it is spent. Deriving that from the state rather than
        // writing a second record makes it exact: there is no window in which
        // the account is durable and the token is still alive.
        if found.kind == TokenKind::Root && !self.state.users.is_empty() {
            return None;
        }

        Some(Caller {
            token_id: found.id.clone(),
            kind: found.kind,
            user_id: found.user_id.clone(),
            project_id: found.project_id.clone(),
            environment_id: found.environment_id.clone(),
        })
    }

    fn issue_token(
        &mut self,
        kind: TokenKind,
        user_id: Option<String>,
        project_id: Option<String>,
        environment_id: Option<String>,
        label: Option<&str>,
        ttl_seconds: Option<i64>,
    ) -> Result<Zeroizing<String>, VaultError> {
        let issued = token::generate().map_err(|_| VaultError::Crypto)?;
        let id = new_id()?;

        self.commit(Event::TokenIssued {
            id,
            token_hash: issued.hash().as_bytes().to_vec(),
            kind,
            user_id,
            project_id,
            environment_id,
            label: label.map(str::to_owned),
            expires_at: ttl_seconds.map(|ttl| Timestamp::now().plus_seconds(ttl)),
            created_at: Timestamp::now(),
        })?;

        Ok(issued.into_secret())
    }

    // --- projects and environments -----------------------------------------

    /// Create a project, with a data key of its own.
    pub fn create_project(
        &mut self,
        caller: &Caller,
        slug: &str,
        name: &str,
    ) -> Result<String, VaultError> {
        self.require_unsealed()?;
        self.require(caller, Capability::Administer)?;
        let slug = validate::slug(slug, "project slug")?;

        if self.state.project_by_slug(&slug).is_some() {
            return Err(VaultError::Conflict("project"));
        }

        let id = new_id()?;
        let data_key = DataKey::generate().map_err(|_| VaultError::Crypto)?;
        let root_key = self.root_key.as_ref().ok_or(VaultError::Sealed)?;
        let wrapped = root_key
            .wrap(&data_key, &project_key_context(&id))
            .map_err(|_| VaultError::Crypto)?;

        self.commit(Event::ProjectCreated {
            id: id.clone(),
            slug,
            name: name.to_owned(),
            data_key: Sealed::from(wrapped),
            created_at: Timestamp::now(),
        })?;

        Ok(id)
    }

    /// Create an environment inside a project.
    pub fn create_environment(
        &mut self,
        caller: &Caller,
        project_slug: &str,
        slug: &str,
        name: &str,
    ) -> Result<String, VaultError> {
        self.require_unsealed()?;
        self.require(caller, Capability::Administer)?;
        let slug = validate::slug(slug, "environment slug")?;

        let project_id = self
            .state
            .project_by_slug(project_slug)
            .ok_or(VaultError::NotFound("project"))?
            .id
            .clone();

        if self.state.environment_by_slug(&project_id, &slug).is_some() {
            return Err(VaultError::Conflict("environment"));
        }

        let id = new_id()?;
        self.commit(Event::EnvironmentCreated {
            id: id.clone(),
            project_id,
            slug,
            name: name.to_owned(),
            created_at: Timestamp::now(),
        })?;

        Ok(id)
    }

    /// Every project slug, in creation order.
    pub fn project_slugs(&self, caller: &Caller) -> Result<Vec<String>, VaultError> {
        self.require_unsealed()?;
        self.require(caller, Capability::Administer)?;
        Ok(self
            .state
            .projects
            .iter()
            .map(|project| project.slug.clone())
            .collect())
    }

    /// Every environment slug of a project.
    pub fn environment_slugs(
        &self,
        caller: &Caller,
        project_slug: &str,
    ) -> Result<Vec<String>, VaultError> {
        self.require_unsealed()?;
        self.require(caller, Capability::Administer)?;
        let project = self
            .state
            .project_by_slug(project_slug)
            .ok_or(VaultError::NotFound("project"))?;

        Ok(self
            .state
            .environments_in(&project.id)
            .iter()
            .map(|env| env.slug.clone())
            .collect())
    }

    // --- secrets -----------------------------------------------------------

    /// Write a secret.
    pub fn set_secret(
        &mut self,
        caller: &Caller,
        project_slug: &str,
        environment_slug: &str,
        key: &str,
        value: &[u8],
    ) -> Result<(), VaultError> {
        self.require_unsealed()?;
        let key = validate::secret_key(key)?;
        let target = format!("{project_slug}/{environment_slug}/{key}");
        let (project_id, environment_id) = self.resolve_and_record(
            caller,
            "secret.set",
            project_slug,
            environment_slug,
            &target,
        )?;

        if let Err(error) = self.authorise(
            caller,
            Capability::WriteSecrets,
            &project_id,
            &environment_id,
        ) {
            self.record_audit(caller, "secret.set", &target, "denied")?;
            return Err(error);
        }

        let data_key = self.project_data_key(&project_id)?;
        let sealed = data_key
            .seal(value, &secret_context(&project_id, &environment_id, &key))
            .map_err(|error| match error {
                ls_core::crypto::aead::AeadError::PlaintextTooLarge { len, max } => {
                    VaultError::ValueTooLarge { len, limit: max }
                }
                _ => VaultError::Crypto,
            })?;

        self.commit(Event::SecretSet {
            project_id,
            environment_id,
            key,
            value: Sealed::from(sealed),
            at: Timestamp::now(),
        })?;

        self.record_audit(caller, "secret.set", &target, "ok")
    }

    /// Read a secret.
    pub fn get_secret(
        &mut self,
        caller: &Caller,
        project_slug: &str,
        environment_slug: &str,
        key: &str,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.require_unsealed()?;
        let target = format!("{project_slug}/{environment_slug}/{key}");
        let (project_id, environment_id) = self.resolve_and_record(
            caller,
            "secret.read",
            project_slug,
            environment_slug,
            &target,
        )?;

        if let Err(error) = self.authorise(
            caller,
            Capability::ReadSecrets,
            &project_id,
            &environment_id,
        ) {
            self.record_audit(caller, "secret.read", &target, "denied")?;
            return Err(error);
        }

        let Some(stored) = self
            .state
            .secret(&project_id, &environment_id, key)
            .map(|secret| secret.value.clone())
        else {
            self.record_audit(caller, "secret.read", &target, "missing")?;
            return Err(VaultError::NotFound("secret"));
        };

        let data_key = self.project_data_key(&project_id)?;
        let value = data_key
            .open(
                &(&stored).into(),
                &secret_context(&project_id, &environment_id, key),
            )
            .map_err(|_| VaultError::Crypto)?;

        self.record_audit(caller, "secret.read", &target, "ok")?;
        Ok(Zeroizing::new(value))
    }

    /// Read every secret in an environment, sorted by key.
    pub fn list_secrets(
        &mut self,
        caller: &Caller,
        project_slug: &str,
        environment_slug: &str,
    ) -> Result<Vec<RevealedSecret>, VaultError> {
        self.require_unsealed()?;
        let target = format!("{project_slug}/{environment_slug}");
        let (project_id, environment_id) = self.resolve_and_record(
            caller,
            "secret.list",
            project_slug,
            environment_slug,
            &target,
        )?;

        if let Err(error) = self.authorise(
            caller,
            Capability::ReadSecrets,
            &project_id,
            &environment_id,
        ) {
            self.record_audit(caller, "secret.list", &target, "denied")?;
            return Err(error);
        }

        let stored: Vec<(String, Sealed)> = self
            .state
            .secrets_in(&project_id, &environment_id)
            .iter()
            .map(|secret| (secret.key.clone(), secret.value.clone()))
            .collect();

        let data_key = self.project_data_key(&project_id)?;
        let mut out = Vec::with_capacity(stored.len());
        for (key, value) in stored {
            let plain = data_key
                .open(
                    &(&value).into(),
                    &secret_context(&project_id, &environment_id, &key),
                )
                .map_err(|_| VaultError::Crypto)?;
            out.push((key, Zeroizing::new(plain)));
        }

        self.record_audit(caller, "secret.list", &target, "ok")?;
        Ok(out)
    }

    /// Remove a secret.
    pub fn delete_secret(
        &mut self,
        caller: &Caller,
        project_slug: &str,
        environment_slug: &str,
        key: &str,
    ) -> Result<(), VaultError> {
        self.require_unsealed()?;
        let target = format!("{project_slug}/{environment_slug}/{key}");
        let (project_id, environment_id) = self.resolve_and_record(
            caller,
            "secret.delete",
            project_slug,
            environment_slug,
            &target,
        )?;

        if let Err(error) = self.authorise(
            caller,
            Capability::WriteSecrets,
            &project_id,
            &environment_id,
        ) {
            self.record_audit(caller, "secret.delete", &target, "denied")?;
            return Err(error);
        }

        if self
            .state
            .secret(&project_id, &environment_id, key)
            .is_none()
        {
            return Err(VaultError::NotFound("secret"));
        }

        self.commit(Event::SecretDeleted {
            project_id,
            environment_id,
            key: key.to_owned(),
            at: Timestamp::now(),
        })?;

        self.record_audit(caller, "secret.delete", &target, "ok")
    }

    // --- audit -------------------------------------------------------------

    /// Every audit entry, oldest first. Requires an unsealed vault, because
    /// the trail lives in the same sealed log as everything else.
    pub fn audit_trail(&mut self, caller: &Caller) -> Result<Vec<AuditEntry>, VaultError> {
        self.require(caller, Capability::Administer)?;
        let root_key = self.root_key.as_ref().ok_or(VaultError::Sealed)?;
        let records = self.log.read_records(root_key)?;

        let mut out = Vec::new();
        for record in records {
            if !record.sealed {
                continue;
            }
            if let Ok(Event::Audited {
                at,
                actor,
                action,
                target,
                outcome,
            }) = Event::from_bytes(&record.payload)
            {
                out.push(AuditEntry {
                    at,
                    actor,
                    action,
                    target,
                    outcome,
                });
            }
        }
        Ok(out)
    }

    fn record_audit(
        &mut self,
        caller: &Caller,
        action: &str,
        target: &str,
        outcome: &str,
    ) -> Result<(), VaultError> {
        self.commit(Event::Audited {
            at: Timestamp::now(),
            actor: caller.actor(),
            action: action.to_owned(),
            target: target.to_owned(),
            outcome: outcome.to_owned(),
        })
    }

    // --- shared helpers ----------------------------------------------------

    /// Write to the log first, then apply. Never the other way round.
    fn commit(&mut self, event: Event) -> Result<(), VaultError> {
        let root_key = self.root_key.as_ref().ok_or(VaultError::Sealed)?;
        self.log.append(root_key, &event.to_bytes())?;
        self.state.apply(event);
        Ok(())
    }

    fn require_unsealed(&self) -> Result<(), VaultError> {
        if self.is_sealed() {
            return Err(VaultError::Sealed);
        }
        Ok(())
    }

    fn resolve(
        &self,
        project_slug: &str,
        environment_slug: &str,
    ) -> Result<(String, String), VaultError> {
        let project = self
            .state
            .project_by_slug(project_slug)
            .ok_or(VaultError::NotFound("project"))?;
        let environment = self
            .state
            .environment_by_slug(&project.id, environment_slug)
            .ok_or(VaultError::NotFound("environment"))?;

        Ok((project.id.clone(), environment.id.clone()))
    }

    /// Resolve for a caller, telling a confined one nothing it should not know.
    ///
    /// Answering "no such project" for a name that is absent and "not allowed"
    /// for one that is present hands a machine token a free listing of
    /// everything on the server. For such a caller both answers become the
    /// same refusal.
    fn resolve_for(
        &self,
        caller: &Caller,
        project_slug: &str,
        environment_slug: &str,
    ) -> Result<(String, String), VaultError> {
        match self.resolve(project_slug, environment_slug) {
            Ok(pair) => Ok(pair),
            Err(_) if caller.kind == TokenKind::Machine => Err(VaultError::Forbidden),
            Err(error) => Err(error),
        }
    }

    /// Resolve, recording the attempt if the name is not there.
    ///
    /// Someone walking the name space leaves no trace otherwise: the request
    /// fails before it reaches the point where operations are recorded, so an
    /// operator reading the trail sees nothing at all.
    fn resolve_and_record(
        &mut self,
        caller: &Caller,
        action: &str,
        project_slug: &str,
        environment_slug: &str,
        target: &str,
    ) -> Result<(String, String), VaultError> {
        match self.resolve_for(caller, project_slug, environment_slug) {
            Ok(pair) => Ok(pair),
            Err(error) => {
                self.record_audit(caller, action, target, "unknown")?;
                Err(error)
            }
        }
    }

    /// Check that a write would be allowed and is well formed, without writing.
    ///
    /// Used to validate a whole batch before any of it is committed.
    pub fn check_secret(
        &self,
        caller: &Caller,
        project_slug: &str,
        environment_slug: &str,
        key: &str,
        value: &[u8],
    ) -> Result<(), VaultError> {
        self.require_unsealed()?;
        validate::secret_key(key)?;
        if value.len() > ls_core::crypto::aead::MAX_PLAINTEXT_LEN {
            return Err(VaultError::ValueTooLarge {
                len: value.len(),
                limit: ls_core::crypto::aead::MAX_PLAINTEXT_LEN,
            });
        }

        let (project_id, environment_id) =
            self.resolve_for(caller, project_slug, environment_slug)?;
        self.authorise(
            caller,
            Capability::WriteSecrets,
            &project_id,
            &environment_id,
        )
    }

    /// Check a capability on its own.
    fn require(&self, caller: &Caller, capability: Capability) -> Result<(), VaultError> {
        if capability.granted_to(caller.kind) {
            Ok(())
        } else {
            Err(VaultError::Forbidden)
        }
    }

    /// Check a capability and, for a machine token, that this is the one
    /// environment it was issued for.
    fn authorise(
        &self,
        caller: &Caller,
        capability: Capability,
        project_id: &str,
        environment_id: &str,
    ) -> Result<(), VaultError> {
        self.require(caller, capability)?;

        if caller.kind != TokenKind::Machine {
            return Ok(());
        }
        let allowed = caller.project_id.as_deref() == Some(project_id)
            && caller.environment_id.as_deref() == Some(environment_id);

        if allowed {
            Ok(())
        } else {
            Err(VaultError::Forbidden)
        }
    }

    fn project_data_key(&self, project_id: &str) -> Result<DataKey, VaultError> {
        let root_key = self.root_key.as_ref().ok_or(VaultError::Sealed)?;
        let project = self
            .state
            .project(project_id)
            .ok_or(VaultError::NotFound("project"))?;

        root_key
            .unwrap_key(
                &(&project.data_key).into(),
                &project_key_context(project_id),
            )
            .map_err(|_| VaultError::Crypto)
    }
}

/// Longest token lifetime accepted, in seconds. Beyond this an expiry could
/// fall outside the timestamp format, and a value that cannot be read back
/// would break the replay permanently on the next restart.
const MAX_LIFETIME_SECONDS: i64 = 100 * 365 * 86_400;

fn check_lifetime(seconds: i64) -> Result<(), VaultError> {
    // Not `abs`: i64::MIN has no positive counterpart and negating it panics.
    if !(-MAX_LIFETIME_SECONDS..=MAX_LIFETIME_SECONDS).contains(&seconds) {
        return Err(VaultError::Invalid("token lifetime"));
    }
    Ok(())
}

/// Associated data binding a data key to the project that owns it, so a key
/// moved onto another project's row will not unwrap.
fn project_key_context(project_id: &str) -> Aad {
    Aad::key_wrap("project-dek", project_id)
}

/// Associated data binding a value to its slot.
fn secret_context(project_id: &str, environment_id: &str, key: &str) -> Aad {
    Aad::secret_slot(project_id, environment_id, key)
}

/// A fresh identifier, or nothing at all.
///
/// There is deliberately no fallback. A clock reading looked like a reasonable
/// one until you notice two environments created in the same second would share
/// an identifier, and then a machine token scoped to one of them passes the
/// check for the other. Refusing is the only safe answer, and matches the rest
/// of the project: entropy failure stops the operation rather than degrading it.
fn new_id() -> Result<String, VaultError> {
    let bytes = random::bytes::<16>().map_err(|_| VaultError::Crypto)?;
    Ok(ls_core::encoding::hex::encode(&bytes))
}

/// A well-formed argon2id hash of a password nobody has. Verifying against it
/// makes an unknown account cost the same as a wrong password.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$\
c29tZXNhbHRzb21lc2FsdA$JQm3CgPlmhCvmSGN0j3T9y9YJCLTrkLMBmU5PGPZUMs";
