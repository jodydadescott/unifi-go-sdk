package unifi

type Device struct {
	Anomalies                           int            `json:"anomalies"`
	ApMac                               string         `json:"ap_mac,omitempty"`
	AssocTime                           int            `json:"assoc_time"`
	Authorized                          bool           `json:"authorized"`
	Blocked                             bool           `json:"blocked"`
	Bssid                               string         `json:"bssid,omitempty"`
	Ccq                                 int            `json:"ccq,omitempty"`
	Channel                             int            `json:"channel,omitempty"`
	ChannelWidth                        string         `json:"channel_width,omitempty"`
	DhcpendTime                         int            `json:"dhcpend_time,omitempty"`
	DisplayName                         string         `json:"display_name"`
	Essid                               string         `json:"essid,omitempty"`
	Fingerprint                         *Fingerprint   `json:"fingerprint,omitempty"`
	FirstSeen                           int            `json:"first_seen"`
	FixedApEnabled                      bool           `json:"fixed_ap_enabled,omitempty"`
	FixedIP                             string         `json:"fixed_ip,omitempty"`
	GwMac                               string         `json:"gw_mac"`
	Hostname                            string         `json:"hostname"`
	Note                                string         `json:"note,omitempty"`
	ID                                  string         `json:"id"`
	Idletime                            int            `json:"idletime,omitempty"`
	IP                                  string         `json:"ip"`
	Ipv4LeaseExpirationTimestampSeconds int            `json:"ipv4_lease_expiration_timestamp_seconds"`
	IsGuest                             bool           `json:"is_guest"`
	IsWired                             bool           `json:"is_wired"`
	LastSeen                            int            `json:"last_seen"`
	LatestAssocTime                     int            `json:"latest_assoc_time"`
	LocalDNSRecord                      string         `json:"local_dns_record,omitempty"`
	LocalDNSRecordEnabled               bool           `json:"local_dns_record_enabled"`
	Mac                                 string         `json:"mac"`
	Mimo                                string         `json:"mimo,omitempty"`
	NetworkID                           string         `json:"network_id"`
	NetworkName                         string         `json:"network_name"`
	Noise                               int            `json:"noise,omitempty"`
	Noted                               bool           `json:"noted"`
	Oui                                 string         `json:"oui"`
	PowersaveEnabled                    bool           `json:"powersave_enabled,omitempty"`
	Radio                               string         `json:"radio,omitempty"`
	RadioName                           string         `json:"radio_name,omitempty"`
	RadioProto                          string         `json:"radio_proto,omitempty"`
	RateImbalance                       int            `json:"rate_imbalance,omitempty"`
	Rssi                                int            `json:"rssi,omitempty"`
	RxBytes                             int            `json:"rx_bytes"`
	RxBytesR                            int            `json:"rx_bytes-r,omitempty"`
	RxPackets                           int            `json:"rx_packets"`
	RxRate                              int            `json:"rx_rate,omitempty"`
	Signal                              int            `json:"signal,omitempty"`
	SiteID                              string         `json:"site_id"`
	Status                              string         `json:"status"`
	TxBytes                             int            `json:"tx_bytes"`
	TxBytesR                            int            `json:"tx_bytes-r,omitempty"`
	TxMcsIndex                          int            `json:"tx_mcs_index,omitempty"`
	TxPackets                           int            `json:"tx_packets"`
	TxRate                              int            `json:"tx_rate,omitempty"`
	Type                                string         `json:"type"`
	UnifiDevice                         bool           `json:"unifi_device"`
	UplinkMac                           string         `json:"uplink_mac"`
	Uptime                              int            `json:"uptime"`
	UsageBytes                          float64        `json:"usage_bytes"`
	UseFixedip                          bool           `json:"use_fixedip"`
	UserID                              string         `json:"user_id"`
	UsergroupID                         string         `json:"usergroup_id"`
	VirtualNetworkOverrideEnabled       bool           `json:"virtual_network_override_enabled"`
	VirtualNetworkOverrideID            string         `json:"virtual_network_override_id,omitempty"`
	WifiExperienceAverage               int            `json:"wifi_experience_average,omitempty"`
	WifiExperienceScore                 int            `json:"wifi_experience_score,omitempty"`
	WifiTxAttempts                      int            `json:"wifi_tx_attempts,omitempty"`
	WlanconfID                          string         `json:"wlanconf_id,omitempty"`
	Name                                string         `json:"name,omitempty"`
	Vlan                                int            `json:"vlan,omitempty"`
	FixedApMac                          string         `json:"fixed_ap_mac,omitempty"`
	DetailedStates                      DetailedStates `json:"detailed_states,omitempty"`
	SwPort                              int            `json:"sw_port,omitempty"`
	WiredRateMbps                       int            `json:"wired_rate_mbps,omitempty"`
	Ipv6Address                         []string       `json:"ipv6_address,omitempty"`
}

type Fingerprint struct {
	ComputedDevID  int  `json:"computed_dev_id"`
	ComputedEngine int  `json:"computed_engine"`
	Confidence     int  `json:"confidence"`
	DevCat         int  `json:"dev_cat"`
	DevFamily      int  `json:"dev_family"`
	DevID          int  `json:"dev_id"`
	DevVendor      int  `json:"dev_vendor"`
	HasOverride    bool `json:"has_override"`
	OsName         int  `json:"os_name"`
	OsClass        int  `json:"os_class"`
}

type DetailedStates struct {
	UplinkNearPowerLimit bool `json:"uplink_near_power_limit"`
}

type AuthRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Token      string `json:"token"`
	RememberMe bool   `json:"rememberMe"`
}

type AuthResponse struct {
	UniqueID           string `json:"unique_id"`
	FirstName          string `json:"first_name"`
	LastName           string `json:"last_name"`
	Alias              string `json:"alias"`
	FullName           string `json:"full_name"`
	Email              string `json:"email"`
	EmailStatus        string `json:"email_status"`
	EmailIsNull        bool   `json:"email_is_null"`
	Phone              string `json:"phone"`
	AvatarRelativePath string `json:"avatar_relative_path"`
	AvatarRpath2       string `json:"avatar_rpath2"`
	Status             string `json:"status"`
	EmployeeNumber     string `json:"employee_number"`
	CreateTime         int    `json:"create_time"`
	Extras             struct {
	} `json:"extras"`
	LoginTime         int    `json:"login_time"`
	Username          string `json:"username"`
	LocalAccountExist bool   `json:"local_account_exist"`
	PasswordRevision  int    `json:"password_revision"`
	OnlyUIAccount     bool   `json:"only_ui_account"`
	OnlyLocalAccount  bool   `json:"only_local_account"`
	SsoAccount        string `json:"sso_account"`
	SsoUUID           string `json:"sso_uuid"`
	SsoUsername       string `json:"sso_username"`
	SsoPicture        string `json:"sso_picture"`
	UIDSsoID          string `json:"uid_sso_id"`
	UIDSsoAccount     string `json:"uid_sso_account"`
	UIDAccountStatus  string `json:"uid_account_status"`
	Groups            []struct {
		UniqueID   string `json:"unique_id"`
		Name       string `json:"name"`
		UpID       string `json:"up_id"`
		UpIds      any    `json:"up_ids"`
		SystemName string `json:"system_name"`
		CreateTime string `json:"create_time"`
	} `json:"groups"`
	Roles []struct {
		UniqueID   string `json:"unique_id"`
		Name       string `json:"name"`
		SystemRole bool   `json:"system_role"`
		SystemKey  string `json:"system_key"`
		Level      int    `json:"level"`
		CreateTime string `json:"create_time"`
		UpdateTime string `json:"update_time"`
		IsPrivate  bool   `json:"is_private"`
	} `json:"roles"`
	Permissions struct {
		AccessManagement         []string `json:"access.management"`
		CalculusManagement       []string `json:"calculus.management"`
		ConnectManagement        []string `json:"connect.management"`
		DriveManagement          []string `json:"drive.management"`
		LedManagement            []string `json:"led.management"`
		NetworkManagement        []string `json:"network.management"`
		OlympusManagement        []string `json:"olympus.management"`
		ProtectManagement        []string `json:"protect.management"`
		SystemManagementLocation []string `json:"system.management.location"`
		SystemManagementUser     []string `json:"system.management.user"`
		TalkManagement           []string `json:"talk.management"`
	} `json:"permissions"`
	Scopes             []string `json:"scopes"`
	CloudAccessGranted bool     `json:"cloud_access_granted"`
	UpdateTime         int      `json:"update_time"`
	Avatar             any      `json:"avatar"`
	NfcToken           string   `json:"nfc_token"`
	NfcDisplayID       string   `json:"nfc_display_id"`
	NfcCardType        string   `json:"nfc_card_type"`
	NfcCardStatus      string   `json:"nfc_card_status"`
	Role               string   `json:"role"`
	ID                 string   `json:"id"`
	IsOwner            bool     `json:"isOwner"`
	IsSuperAdmin       bool     `json:"isSuperAdmin"`
	IsMember           bool     `json:"isMember"`
	UcorePermission    struct {
		HasViewUserPermission         bool `json:"hasViewUserPermission"`
		HasEditUserPermission         bool `json:"hasEditUserPermission"`
		HasViewSettingsPermission     bool `json:"hasViewSettingsPermission"`
		HasUpdateChannelPermission    bool `json:"hasUpdateChannelPermission"`
		HasGeneralSettingsPermission  bool `json:"hasGeneralSettingsPermission"`
		HasUpdateAndInstallPermission bool `json:"hasUpdateAndInstallPermission"`
		HasAutoUpdatePermission       bool `json:"hasAutoUpdatePermission"`
		HasNotificationPermission     bool `json:"hasNotificationPermission"`
		HasRemoteAccessPermission     bool `json:"hasRemoteAccessPermission"`
		HasBackupPermission           bool `json:"hasBackupPermission"`
		HasRestartConsolePermission   bool `json:"hasRestartConsolePermission"`
		HasPoweroffConsolePermission  bool `json:"hasPoweroffConsolePermission"`
		HasResetConsolePermission     bool `json:"hasResetConsolePermission"`
		HasTransferOwnerPermission    bool `json:"hasTransferOwnerPermission"`
		HasSSHPermission              bool `json:"hasSSHPermission"`
		HasSupportFilePermission      bool `json:"hasSupportFilePermission"`
	} `json:"ucorePermission"`
	MaskedEmail string `json:"maskedEmail"`
	DeviceToken string `json:"deviceToken"`
	SsoAuth     struct {
	} `json:"ssoAuth"`
}
