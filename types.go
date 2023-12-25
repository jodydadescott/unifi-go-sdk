package unifi

import (
	"time"

	"github.com/jinzhu/copier"
)

type Config struct {
	Enabled  bool          `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Username string        `json:"username,omitempty" yaml:"username,omitempty"`
	Password string        `json:"password,omitempty" yaml:"password,omitempty"`
	Hostname string        `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	Timeout  time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// Clone return copy
func (t *Config) Clone() *Config {
	c := &Config{}
	copier.Copy(&c, &t)
	return c
}

func ExampleConfig() *Config {
	return &Config{
		Username: "my_unifi_username",
		Password: "my_unifi_password",
		Hostname: "https://...",
	}
}

type UnifiClient struct {
	// /proxy/network/v2/api/site/default/clients/active?includeTrafficUsage=true&includeUnifiDevices=true"
	Anomalies                           float64        `json:"anomalies"`
	ApMac                               string         `json:"ap_mac,omitempty"`
	AssocTime                           float64        `json:"assoc_time"`
	Authorized                          bool           `json:"authorized"`
	Blocked                             bool           `json:"blocked"`
	Bssid                               string         `json:"bssid,omitempty"`
	Ccq                                 float64        `json:"ccq,omitempty"`
	Channel                             float64        `json:"channel,omitempty"`
	ChannelWidth                        string         `json:"channel_width,omitempty"`
	DhcpendTime                         float64        `json:"dhcpend_time,omitempty"`
	DisplayName                         string         `json:"display_name"`
	Essid                               string         `json:"essid,omitempty"`
	Fingerprint                         *Fingerprint   `json:"fingerprint,omitempty"`
	FirstSeen                           float64        `json:"first_seen"`
	FixedApEnabled                      bool           `json:"fixed_ap_enabled,omitempty"`
	FixedIP                             string         `json:"fixed_ip,omitempty"`
	GwMac                               string         `json:"gw_mac"`
	Hostname                            string         `json:"hostname"`
	Note                                string         `json:"note,omitempty"`
	ID                                  string         `json:"id"`
	Idletime                            float64        `json:"idletime,omitempty"`
	IP                                  string         `json:"ip"`
	Ipv4LeaseExpirationTimestampSeconds float64        `json:"ipv4_lease_expiration_timestamp_seconds"`
	IsGuest                             bool           `json:"is_guest"`
	IsWired                             bool           `json:"is_wired"`
	LastSeen                            float64        `json:"last_seen"`
	LatestAssocTime                     float64        `json:"latest_assoc_time"`
	LocalDNSRecord                      string         `json:"local_dns_record,omitempty"`
	LocalDNSRecordEnabled               bool           `json:"local_dns_record_enabled"`
	Mac                                 string         `json:"mac"`
	Mimo                                string         `json:"mimo,omitempty"`
	NetworkID                           string         `json:"network_id"`
	NetworkName                         string         `json:"network_name"`
	Noise                               float64        `json:"noise,omitempty"`
	Noted                               bool           `json:"noted"`
	Oui                                 string         `json:"oui"`
	PowersaveEnabled                    bool           `json:"powersave_enabled,omitempty"`
	Radio                               string         `json:"radio,omitempty"`
	RadioName                           string         `json:"radio_name,omitempty"`
	RadioProto                          string         `json:"radio_proto,omitempty"`
	RateImbalance                       float64        `json:"rate_imbalance,omitempty"`
	Rssi                                float64        `json:"rssi,omitempty"`
	RxBytes                             float64        `json:"rx_bytes"`
	RxBytesR                            float64        `json:"rx_bytes-r,omitempty"`
	RxPackets                           float64        `json:"rx_packets"`
	RxRate                              float64        `json:"rx_rate,omitempty"`
	Signal                              float64        `json:"signal,omitempty"`
	SiteID                              string         `json:"site_id"`
	Status                              string         `json:"status"`
	TxBytes                             float64        `json:"tx_bytes"`
	TxBytesR                            float64        `json:"tx_bytes-r,omitempty"`
	TxMcsIndex                          float64        `json:"tx_mcs_index,omitempty"`
	TxPackets                           float64        `json:"tx_packets"`
	TxRate                              float64        `json:"tx_rate,omitempty"`
	Type                                string         `json:"type"`
	UnifiDevice                         bool           `json:"unifi_device"`
	UplinkMac                           string         `json:"uplink_mac"`
	Uptime                              float64        `json:"uptime"`
	UsageBytes                          float64        `json:"usage_bytes"`
	UseFixedip                          bool           `json:"use_fixedip"`
	UserID                              string         `json:"user_id"`
	UsergroupID                         string         `json:"usergroup_id"`
	VirtualNetworkOverrideEnabled       bool           `json:"virtual_network_override_enabled"`
	VirtualNetworkOverrideID            string         `json:"virtual_network_override_id,omitempty"`
	WifiExperienceAverage               float64        `json:"wifi_experience_average,omitempty"`
	WifiExperienceScore                 float64        `json:"wifi_experience_score,omitempty"`
	WifiTxAttempts                      float64        `json:"wifi_tx_attempts,omitempty"`
	WlanconfID                          string         `json:"wlanconf_id,omitempty"`
	Name                                string         `json:"name,omitempty"`
	Vlan                                float64        `json:"vlan,omitempty"`
	FixedApMac                          string         `json:"fixed_ap_mac,omitempty"`
	DetailedStates                      DetailedStates `json:"detailed_states,omitempty"`
	SwPort                              float64        `json:"sw_port,omitempty"`
	WiredRateMbps                       float64        `json:"wired_rate_mbps,omitempty"`
	Ipv6Address                         []string       `json:"ipv6_address,omitempty"`
}

type Fingerprint struct {
	ComputedDevID  float64 `json:"computed_dev_id"`
	ComputedEngine float64 `json:"computed_engine"`
	Confidence     float64 `json:"confidence"`
	DevCat         float64 `json:"dev_cat"`
	DevFamily      float64 `json:"dev_family"`
	DevID          float64 `json:"dev_id"`
	DevVendor      float64 `json:"dev_vendor"`
	HasOverride    bool    `json:"has_override"`
	OsName         float64 `json:"os_name"`
	OsClass        float64 `json:"os_class"`
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
	UniqueID           string  `json:"unique_id"`
	FirstName          string  `json:"first_name"`
	LastName           string  `json:"last_name"`
	Alias              string  `json:"alias"`
	FullName           string  `json:"full_name"`
	Email              string  `json:"email"`
	EmailStatus        string  `json:"email_status"`
	EmailIsNull        bool    `json:"email_is_null"`
	Phone              string  `json:"phone"`
	AvatarRelativePath string  `json:"avatar_relative_path"`
	AvatarRpath2       string  `json:"avatar_rpath2"`
	Status             string  `json:"status"`
	EmployeeNumber     string  `json:"employee_number"`
	CreateTime         float64 `json:"create_time"`
	Extras             struct {
	} `json:"extras"`
	LoginTime         float64 `json:"login_time"`
	Username          string  `json:"username"`
	LocalAccountExist bool    `json:"local_account_exist"`
	PasswordRevision  float64 `json:"password_revision"`
	OnlyUIAccount     bool    `json:"only_ui_account"`
	OnlyLocalAccount  bool    `json:"only_local_account"`
	SsoAccount        string  `json:"sso_account"`
	SsoUUID           string  `json:"sso_uuid"`
	SsoUsername       string  `json:"sso_username"`
	SsoPicture        string  `json:"sso_picture"`
	UIDSsoID          string  `json:"uid_sso_id"`
	UIDSsoAccount     string  `json:"uid_sso_account"`
	UIDAccountStatus  string  `json:"uid_account_status"`
	Groups            []struct {
		UniqueID   string `json:"unique_id"`
		Name       string `json:"name"`
		UpID       string `json:"up_id"`
		UpIds      any    `json:"up_ids"`
		SystemName string `json:"system_name"`
		CreateTime string `json:"create_time"`
	} `json:"groups"`
	Roles []struct {
		UniqueID   string  `json:"unique_id"`
		Name       string  `json:"name"`
		SystemRole bool    `json:"system_role"`
		SystemKey  string  `json:"system_key"`
		Level      float64 `json:"level"`
		CreateTime string  `json:"create_time"`
		UpdateTime string  `json:"update_time"`
		IsPrivate  bool    `json:"is_private"`
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
	UpdateTime         float64  `json:"update_time"`
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

type UnifiDevices struct {
	//  /proxy/network/v2/api/site/default/device?separateUnmanaged=true&includeTrafficUsage=true
	AccessDevices    []any            `json:"access_devices"`
	ConnectDevices   []any            `json:"connect_devices"`
	LedDevices       []any            `json:"led_devices"`
	NetworkDevices   []NetworkDevices `json:"network_devices"`
	ProtectDevices   []any            `json:"protect_devices"`
	TalkDevices      []any            `json:"talk_devices"`
	UnmanagedDevices []any            `json:"unmanaged_devices"`
}

type RadioTable struct {
	AntennaGain           float64 `json:"antenna_gain"`
	BuiltinAntGain        float64 `json:"builtin_ant_gain"`
	BuiltinAntenna        bool    `json:"builtin_antenna"`
	Channel               float64 `json:"channel"`
	CurrentAntennaGain    float64 `json:"current_antenna_gain"`
	HardNoiseFloorEnabled bool    `json:"hard_noise_floor_enabled"`
	HasDfs                bool    `json:"has_dfs"`
	HasFccdfs             bool    `json:"has_fccdfs"`
	HasHt160              bool    `json:"has_ht160"`
	HasRestrictedChannels bool    `json:"has_restricted_channels"`
	Ht                    float64 `json:"ht"`
	Is11Ac                bool    `json:"is_11ac"`
	Is11Ax                bool    `json:"is_11ax"`
	LoadbalanceEnabled    bool    `json:"loadbalance_enabled"`
	MaxTxpower            float64 `json:"max_txpower"`
	MinRssiEnabled        bool    `json:"min_rssi_enabled"`
	MinTxpower            float64 `json:"min_txpower"`
	Name                  string  `json:"name"`
	Nss                   float64 `json:"nss"`
	Radio                 string  `json:"radio"`
	RadioCaps             float64 `json:"radio_caps"`
	RadioCaps2            float64 `json:"radio_caps2"`
	SensLevelEnabled      bool    `json:"sens_level_enabled"`
	TxPowerMode           string  `json:"tx_power_mode"`
	VwireEnabled          bool    `json:"vwire_enabled"`
}

type RadioTableStats struct {
	Channel      float64 `json:"channel"`
	CuSelfRx     float64 `json:"cu_self_rx"`
	CuSelfTx     float64 `json:"cu_self_tx"`
	CuTotal      float64 `json:"cu_total"`
	Extchannel   float64 `json:"extchannel"`
	Gain         float64 `json:"gain"`
	GuestNumSta  float64 `json:"guest-num_sta"`
	Name         string  `json:"name"`
	NumSta       float64 `json:"num_sta"`
	Radio        string  `json:"radio"`
	Satisfaction float64 `json:"satisfaction"`
	State        string  `json:"state"`
	TxPackets    float64 `json:"tx_packets"`
	TxPower      float64 `json:"tx_power"`
	TxRetries    float64 `json:"tx_retries"`
	UserNumSta   float64 `json:"user-num_sta"`
}

type SysStats struct {
	Loadavg1  float64 `json:"loadavg_1"`
	Loadavg15 float64 `json:"loadavg_15"`
	Loadavg5  float64 `json:"loadavg_5"`
	MemBuffer float64 `json:"mem_buffer"`
	MemTotal  float64 `json:"mem_total"`
	MemUsed   float64 `json:"mem_used"`
}

type SystemStats struct {
	CPU    float64 `json:"cpu"`
	Mem    float64 `json:"mem"`
	Uptime float64 `json:"uptime"`
}

type Uplink struct {
	Mac              string  `json:"mac"`
	Name             string  `json:"name"`
	PortIdx          float64 `json:"port_idx"`
	Speed            float64 `json:"speed"`
	Type             string  `json:"type"`
	UplinkDeviceName string  `json:"uplink_device_name"`
	UplinkMac        string  `json:"uplink_mac"`
	UplinkRemotePort float64 `json:"uplink_remote_port"`
	ApMac            string  `json:"ap_mac"`
	Essid            string  `json:"essid"`
	RadioBand        string  `json:"radio_band"`
}

type VapTable struct {
	ApMac        string  `json:"ap_mac"`
	Bssid        string  `json:"bssid"`
	Bw           float64 `json:"bw"`
	Channel      float64 `json:"channel"`
	Essid        string  `json:"essid"`
	IsGuest      bool    `json:"is_guest"`
	Name         string  `json:"name"`
	NumSta       float64 `json:"num_sta"`
	Radio        string  `json:"radio"`
	RadioName    string  `json:"radio_name"`
	RxBytes      float64 `json:"rx_bytes"`
	RxDropped    float64 `json:"rx_dropped"`
	RxErrors     float64 `json:"rx_errors"`
	RxPackets    float64 `json:"rx_packets"`
	RxRetries    float64 `json:"rx_retries"`
	Satisfaction float64 `json:"satisfaction"`
	TxBytes      float64 `json:"tx_bytes"`
	TxDropped    float64 `json:"tx_dropped"`
	TxErrors     float64 `json:"tx_errors"`
	TxPackets    float64 `json:"tx_packets"`
	TxPower      float64 `json:"tx_power"`
	TxRetries    float64 `json:"tx_retries"`
}

type NetworkDevices struct {
	ID                                  string            `json:"_id"`
	AdoptState                          float64           `json:"adopt_state"`
	AdoptableWhenUpgraded               bool              `json:"adoptable_when_upgraded"`
	Adopted                             bool              `json:"adopted"`
	BytesR                              float64           `json:"bytes-r"`
	ConnectionNetworkID                 string            `json:"connection_network_id,omitempty"`
	ConnectionNetworkName               string            `json:"connection_network_name,omitempty"`
	CountrycodeTable                    []float64         `json:"countrycode_table"`
	Default                             bool              `json:"default"`
	DeviceType                          string            `json:"device_type"`
	Disabled                            bool              `json:"disabled"`
	DiscoveredVia                       string            `json:"discovered_via,omitempty"`
	DisplayableVersion                  string            `json:"displayable_version,omitempty"`
	DownloadSpeedBytesPerSecond         float64           `json:"download_speed_bytes_per_second"`
	EthernetOverrides                   []any             `json:"ethernet_overrides"`
	FwCaps                              float64           `json:"fw_caps"`
	IP                                  string            `json:"ip"`
	Ipv4LeaseExpirationTimestampSeconds float64           `json:"ipv4_lease_expiration_timestamp_seconds,omitempty"`
	IsAccessPoint                       bool              `json:"is_access_point"`
	IsAdoptionQueued                    bool              `json:"is_adoption_queued"`
	Isolated                            bool              `json:"isolated"`
	LastConnectionNetworkID             string            `json:"last_connection_network_id"`
	LastConnectionNetworkName           string            `json:"last_connection_network_name"`
	LastSeen                            float64           `json:"last_seen,omitempty"`
	LastUplink                          Uplink            `json:"last_uplink,omitempty"`
	LicenseState                        string            `json:"license_state"`
	Locating                            bool              `json:"locating"`
	LteConnected                        bool              `json:"lte_connected"`
	Mac                                 string            `json:"mac"`
	Model                               string            `json:"model"`
	ModelInEol                          bool              `json:"model_in_eol"`
	ModelInLts                          bool              `json:"model_in_lts"`
	ModelIncompatible                   bool              `json:"model_incompatible"`
	Name                                string            `json:"name"`
	NumSta                              float64           `json:"num_sta"`
	PortTable                           []Port            `json:"port_table"`
	ProductLine                         string            `json:"product_line"`
	RadioTable                          []RadioTable      `json:"radio_table"`
	RadioTableStats                     []RadioTableStats `json:"radio_table_stats"`
	Restarting                          bool              `json:"restarting"`
	RxBytes                             float64           `json:"rx_bytes"`
	RxBytesD                            float64           `json:"rx_bytes-d"`
	Satisfaction                        float64           `json:"satisfaction"`
	SpectrumScanning                    bool              `json:"spectrum_scanning"`
	State                               float64           `json:"state"`
	SupportWifi6E                       bool              `json:"support_wifi6e,omitempty"`
	SysStats                            SysStats          `json:"sys_stats,omitempty"`
	SystemStats                         SystemStats       `json:"system-stats,omitempty"`
	TxBytes                             float64           `json:"tx_bytes"`
	TxBytesD                            float64           `json:"tx_bytes-d"`
	Type                                string            `json:"type"`
	Unsupported                         bool              `json:"unsupported"`
	UnsupportedReason                   float64           `json:"unsupported_reason"`
	Upgradable                          bool              `json:"upgradable"`
	UpgradeState                        float64           `json:"upgrade_state"`
	Uplink                              Uplink            `json:"uplink,omitempty"`
	UplinkTable                         []any             `json:"uplink_table"`
	UploadSpeedBytesPerSecond           float64           `json:"upload_speed_bytes_per_second"`
	Uptime                              float64           `json:"uptime,omitempty"`
	UsageBytes                          float64           `json:"usage_bytes"`
	VapTable                            []VapTable        `json:"vap_table"`
	Version                             string            `json:"version"`
	WlanOverrides                       []any             `json:"wlan_overrides"`
	LanIP                               string            `json:"lan_ip,omitempty"`
}

type Port struct {
	AggregatedBy bool    `json:"aggregated_by"`
	Autoneg      bool    `json:"autoneg"`
	Enable       bool    `json:"enable"`
	FullDuplex   bool    `json:"full_duplex"`
	Ifname       string  `json:"ifname"`
	IP           string  `json:"ip"`
	IsUplink     bool    `json:"is_uplink"`
	Media        string  `json:"media"`
	Name         string  `json:"name"`
	PoeCaps      float64 `json:"poe_caps"`
	PoeEnable    bool    `json:"poe_enable"`
	PortIdx      float64 `json:"port_idx"`
	PortPoe      bool    `json:"port_poe"`
	RxBytes      float64 `json:"rx_bytes"`
	RxBytesR     float64 `json:"rx_bytes-r"`
	RxDropped    float64 `json:"rx_dropped"`
	RxErrors     float64 `json:"rx_errors"`
	RxPackets    float64 `json:"rx_packets"`
	Satisfaction float64 `json:"satisfaction"`
	Speed        float64 `json:"speed"`
	SpeedCaps    float64 `json:"speed_caps"`
	TxBytes      float64 `json:"tx_bytes"`
	TxBytesR     float64 `json:"tx_bytes-r"`
	TxDropped    float64 `json:"tx_dropped"`
	TxErrors     float64 `json:"tx_errors"`
	TxPackets    float64 `json:"tx_packets"`
	Up           bool    `json:"up"`
}

type EnrichedConfiguration struct {
	// /proxy/network/v2/api/site/default/lan/enriched-configuration
	Configuration Configuration `json:"configuration"`
	Details       Details       `json:"details"`
	Statistics    Statistics    `json:"statistics"`
}

type Configuration struct {
	SettingPreference           string   `json:"setting_preference"`
	Dhcpdv6DNSAuto              bool     `json:"dhcpdv6_dns_auto"`
	Ipv6PdStop                  string   `json:"ipv6_pd_stop"`
	DhcpdGatewayEnabled         bool     `json:"dhcpd_gateway_enabled"`
	Ipv6ClientAddressAssignment string   `json:"ipv6_client_address_assignment"`
	DhcpdDNS1                   string   `json:"dhcpd_dns_1"`
	DhcpdStart                  string   `json:"dhcpd_start"`
	DhcpdUnifiController        string   `json:"dhcpd_unifi_controller"`
	Ipv6RaEnabled               bool     `json:"ipv6_ra_enabled"`
	DomainName                  string   `json:"domain_name"`
	IPSubnet                    string   `json:"ip_subnet"`
	Ipv6InterfaceType           string   `json:"ipv6_interface_type"`
	Dhcpdv6Stop                 string   `json:"dhcpdv6_stop"`
	IsNat                       bool     `json:"is_nat"`
	DhcpdDNSEnabled             bool     `json:"dhcpd_dns_enabled"`
	NatOutboundIPAddresses      []string `json:"nat_outbound_ip_addresses"`
	DhcpRelayEnabled            bool     `json:"dhcp_relay_enabled"`
	IgmpProxyDownstream         bool     `json:"igmp_proxy_downstream"`
	Ipv6PdAutoPrefixidEnabled   bool     `json:"ipv6_pd_auto_prefixid_enabled"`
	SiteID                      string   `json:"site_id"`
	Name                        string   `json:"name"`
	Dhcpdv6Leasetime            float64  `json:"dhcpdv6_leasetime"`
	ID                          string   `json:"_id"`
	LteLanEnabled               bool     `json:"lte_lan_enabled"`
	Purpose                     string   `json:"purpose"`
	DhcpdLeasetime              float64  `json:"dhcpd_leasetime"`
	IgmpSnooping                bool     `json:"igmp_snooping"`
	DhcpguardEnabled            bool     `json:"dhcpguard_enabled"`
	DhcpdTimeOffsetEnabled      bool     `json:"dhcpd_time_offset_enabled"`
	Dhcpdv6AllowSlaac           bool     `json:"dhcpdv6_allow_slaac"`
	Ipv6RaPreferredLifetime     float64  `json:"ipv6_ra_preferred_lifetime"`
	DhcpdStop                   string   `json:"dhcpd_stop"`
	Enabled                     bool     `json:"enabled"`
	DhcpdEnabled                bool     `json:"dhcpd_enabled"`
	DhcpdWpadURL                string   `json:"dhcpd_wpad_url"`
	Networkgroup                string   `json:"networkgroup"`
	Dhcpdv6Start                string   `json:"dhcpdv6_start"`
	VlanEnabled                 bool     `json:"vlan_enabled"`
	Ipv6SettingPreference       string   `json:"ipv6_setting_preference"`
	GatewayType                 string   `json:"gateway_type"`
	Ipv6RaPriority              string   `json:"ipv6_ra_priority"`
	DhcpdBootEnabled            bool     `json:"dhcpd_boot_enabled"`
	Ipv6PdStart                 string   `json:"ipv6_pd_start"`
	UpnpLanEnabled              bool     `json:"upnp_lan_enabled"`
	DhcpdNtpEnabled             bool     `json:"dhcpd_ntp_enabled"`
	MdnsEnabled                 bool     `json:"mdns_enabled"`
	AttrNoDelete                bool     `json:"attr_no_delete"`
	AttrHiddenID                string   `json:"attr_hidden_id"`
	DhcpdTftpServer             string   `json:"dhcpd_tftp_server"`
	AutoScaleEnabled            bool     `json:"auto_scale_enabled"`
}

type Details struct {
	CreationTimestamp    float64 `json:"creation_timestamp"`
	GatewayInterfaceName string  `json:"gateway_interface_name"`
	GatewayMac           string  `json:"gateway_mac"`
}

type Statistics struct {
	DhcpActiveLeases float64 `json:"dhcp_active_leases"`
	DhcpMaxLeases    float64 `json:"dhcp_max_leases"`
}
