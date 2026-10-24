/**
 * Popular products endoflife.date doesn't track, with CPE names checked against the NVD
 * CPE dictionary. Anything else can still be added: Patchbell searches NVD for it.
 */
export interface ExtraEntry {
  slug: string;
  label: string;
  aliases: string[];
  cpe: string;
}

export const EXTRA: ExtraEntry[] = [
  { slug: 'plex', label: 'Plex Media Server', aliases: ['plex-media-server', 'pms'], cpe: 'a:plex:media_server' },
  { slug: 'jellyfin', label: 'Jellyfin', aliases: [], cpe: 'a:jellyfin:jellyfin' },
  { slug: 'home-assistant', label: 'Home Assistant', aliases: ['homeassistant', 'hass'], cpe: 'a:home-assistant:home-assistant' },
  { slug: 'qnap-qts', label: 'QNAP QTS', aliases: ['qts'], cpe: 'o:qnap:qts' },
  { slug: 'unifi-network', label: 'UniFi Network Application', aliases: ['unifi', 'unifi-controller', 'unifi-network-application'], cpe: 'a:ui:unifi_network_application' },
  { slug: 'pfsense', label: 'pfSense', aliases: [], cpe: 'a:netgate:pfsense' },
  { slug: 'vlc', label: 'VLC media player', aliases: ['vlc-media-player'], cpe: 'a:videolan:vlc_media_player' },
  { slug: '7-zip', label: '7-Zip', aliases: ['7zip'], cpe: 'a:7-zip:7-zip' },
  { slug: 'winrar', label: 'WinRAR', aliases: [], cpe: 'a:rarlab:winrar' },
  { slug: 'vscode', label: 'Visual Studio Code', aliases: ['vs-code', 'code'], cpe: 'a:microsoft:visual_studio_code' },
  { slug: '1password', label: '1Password', aliases: [], cpe: 'a:1password:1password' },
  { slug: 'keepassxc', label: 'KeePassXC', aliases: [], cpe: 'a:keepassxc:keepassxc' },
  { slug: 'telegram-desktop', label: 'Telegram Desktop', aliases: ['telegram'], cpe: 'a:telegram:telegram_desktop' },
  { slug: 'tailscale', label: 'Tailscale', aliases: [], cpe: 'a:tailscale:tailscale' },
  { slug: 'openssh', label: 'OpenSSH', aliases: ['ssh', 'sshd'], cpe: 'a:openbsd:openssh' },
  { slug: 'curl', label: 'curl', aliases: ['libcurl'], cpe: 'a:haxx:curl' },
  { slug: 'sudo', label: 'sudo', aliases: [], cpe: 'a:sudo_project:sudo' },
  { slug: 'git', label: 'Git', aliases: [], cpe: 'a:git-scm:git' },
  { slug: 'safari', label: 'Safari', aliases: [], cpe: 'a:apple:safari' },
  { slug: 'edge', label: 'Microsoft Edge', aliases: ['microsoft-edge'], cpe: 'a:microsoft:edge_chromium' },
  { slug: 'thunderbird', label: 'Thunderbird', aliases: [], cpe: 'a:mozilla:thunderbird' },
  { slug: 'openjdk', label: 'OpenJDK', aliases: ['java', 'jdk'], cpe: 'a:oracle:openjdk' },
  { slug: 'ivanti-connect-secure', label: 'Ivanti Connect Secure', aliases: ['pulse-connect-secure'], cpe: 'a:ivanti:connect_secure' },
  { slug: 'exchange', label: 'Microsoft Exchange Server', aliases: ['exchange-server'], cpe: 'a:microsoft:exchange_server' },
  { slug: 'bind', label: 'ISC BIND', aliases: ['bind9', 'named'], cpe: 'a:isc:bind' },
  { slug: 'struts', label: 'Apache Struts', aliases: ['apache-struts'], cpe: 'a:apache:struts' },
  { slug: 'zimbra', label: 'Zimbra Collaboration', aliases: [], cpe: 'a:zimbra:collaboration' },
  { slug: 'n8n', label: 'n8n', aliases: [], cpe: 'a:n8n:n8n' },
  { slug: 'gitea', label: 'Gitea', aliases: [], cpe: 'a:gitea:gitea' },
  { slug: 'pan-os', label: 'PAN-OS', aliases: ['panos', 'palo-alto-pan-os'], cpe: 'o:paloaltonetworks:pan-os' },
  { slug: 'synology-dsm', label: 'Synology DiskStation Manager', aliases: ['dsm', 'synology'], cpe: 'o:synology:diskstation_manager' },
  { slug: 'netscaler-adc', label: 'Citrix NetScaler ADC', aliases: ['netscaler', 'citrix-adc'], cpe: 'a:citrix:netscaler_application_delivery_controller' },
  { slug: 'sonicos', label: 'SonicWall SonicOS', aliases: ['sonicwall'], cpe: 'o:sonicwall:sonicos' },
  { slug: 'crushftp', label: 'CrushFTP', aliases: [], cpe: 'a:crushftp:crushftp' },
  { slug: 'moveit-transfer', label: 'MOVEit Transfer', aliases: ['moveit'], cpe: 'a:progress:moveit_transfer' },
  { slug: 'vaultwarden', label: 'Vaultwarden', aliases: [], cpe: 'a:dani-garcia:vaultwarden' },
  { slug: 'minio', label: 'MinIO', aliases: [], cpe: 'a:minio:minio' },
  { slug: 'ollama', label: 'Ollama', aliases: [], cpe: 'a:ollama:ollama' },
  { slug: 'open-webui', label: 'Open WebUI', aliases: ['openwebui'], cpe: 'a:openwebui:open_webui' },
  { slug: 'langflow', label: 'Langflow', aliases: [], cpe: 'a:langflow:langflow' },
  { slug: 'activemq', label: 'Apache ActiveMQ', aliases: ['apache-activemq'], cpe: 'a:apache:activemq' },
  { slug: 'kafka', label: 'Apache Kafka', aliases: ['apache-kafka'], cpe: 'a:apache:kafka' },
  { slug: 'vault', label: 'HashiCorp Vault', aliases: ['hashicorp-vault'], cpe: 'a:hashicorp:vault' },
  { slug: 'unbound', label: 'Unbound', aliases: [], cpe: 'a:nlnetlabs:unbound' },
  { slug: 'asterisk', label: 'Asterisk', aliases: [], cpe: 'a:sangoma:asterisk' },
  { slug: 'docker-desktop', label: 'Docker Desktop', aliases: [], cpe: 'a:docker:desktop' },
  { slug: 'filezilla', label: 'FileZilla Client', aliases: ['filezilla-client'], cpe: 'a:filezilla-project:filezilla_client' },
  { slug: 'putty', label: 'PuTTY', aliases: [], cpe: 'a:putty:putty' },
];

/** Older CPE names whose CVEs belong to the same product (nginx moved from nginx:nginx to f5:nginx). */
export const ALSO: Record<string, { vendor: string; product: string }[]> = {
  nginx: [{ vendor: 'nginx', product: 'nginx' }],
  plex: [{ vendor: 'plex', product: 'plex_media_server' }],
  asterisk: [{ vendor: 'digium', product: 'asterisk' }],
  putty: [{ vendor: 'simon_tatham', product: 'putty' }],
  zimbra: [{ vendor: 'synacor', product: 'zimbra_collaboration_suite' }],
};

/** Extra names for endoflife.date products. */
export const EXTRA_ALIASES: Record<string, string[]> = {
  routeros: ['mikrotik', 'mikrotik-routeros'],
  'docker-engine': ['docker'],
};
