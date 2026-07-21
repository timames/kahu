"""Config-plane state manager — enforces the two-plane model."""


class ConfigPlaneState:
    """Singleton managing config plane state.

    Rules:
    - Data plane: always on, air-gapped, no external dependencies
    - Config plane: off by default, requires seated token + operator PIN
    - Token removal immediately kills config plane session
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._config_plane_active = False
        self._current_session_id = None
        self._operator = None
        self._token_serial = None
        self._api_credential = None  # Memory-only, never persisted

    @property
    def is_config_plane_active(self) -> bool:
        return self._config_plane_active

    @property
    def current_operator(self) -> str | None:
        return self._operator

    def activate(self, session_id, operator: str, token_serial: str, api_credential: str):
        """Activate config plane. Called after token auth succeeds."""
        self._config_plane_active = True
        self._current_session_id = session_id
        self._operator = operator
        self._token_serial = token_serial
        self._api_credential = api_credential  # Held in memory only

    def deactivate(self):
        """Deactivate config plane and zeroize credentials. Called on token removal."""
        # Zeroize credential in memory
        if self._api_credential:
            self._api_credential = None
        self._config_plane_active = False
        self._current_session_id = None
        self._operator = None
        self._token_serial = None

    def get_api_credential(self) -> str | None:
        """Get API credential. Returns None if config plane is not active."""
        if not self._config_plane_active:
            return None
        return self._api_credential


config_plane = ConfigPlaneState()
