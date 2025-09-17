use std::collections::HashMap;

use serde::{Deserialize, Serialize};

fn serialize_as_json<T, S>(t: &T, s: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: serde::Serializer,
{
    s.serialize_str(&serde_json::to_string(t).map_err(|e| serde::ser::Error::custom(format!("{e}")))?)
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ListContainersOptions {
    /// Return all containers. By default, only running containers are shown
    pub all: bool,
    /// Return this number of most recently created containers, including non-running ones
    pub limit: Option<isize>,
    /// Return the size of container as fields `SizeRw` and `SizeRootFs`
    pub size: bool,

    /// See Docker's documentation to learn how to use filters
    /// https://docs.docker.com/reference/cli/docker/container/ls/#filter
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerSummary {
    /// The ID of this container
    #[serde(rename = "Id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The names that this container has been given
    #[serde(rename = "Names")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,

    /// The name of the image used when creating this container
    #[serde(rename = "Image")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// The ID of the image that this container was created from
    #[serde(rename = "ImageID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_id: Option<String>,

    /// Command to run when starting the container
    #[serde(rename = "Command")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// When the container was created
    #[serde(rename = "Created")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<i64>,

    /// The ports exposed by this container
    #[serde(rename = "Ports")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<Port>>,

    /// The size of files that have been created or changed by this container
    #[serde(rename = "SizeRw")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_rw: Option<i64>,

    /// The total size of all the files in this container
    #[serde(rename = "SizeRootFs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_root_fs: Option<i64>,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    /// The state of this container (e.g. `Exited`)
    #[serde(rename = "State")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// Additional human-readable status of this container (e.g. `Exit 0`)
    #[serde(rename = "Status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    #[serde(rename = "HostConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_config: Option<ContainerSummaryHostConfig>,

    #[serde(rename = "NetworkSettings")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_settings: Option<ContainerSummaryNetworkSettings>,

    #[serde(rename = "Mounts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<MountPoint>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerSummaryHostConfig {
    #[serde(rename = "NetworkMode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_mode: Option<String>,
}

/// A summary of the container's network settings
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerSummaryNetworkSettings {
    #[serde(rename = "Networks")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub networks: Option<HashMap<String, EndpointSettings>>,
}

/// An open port on a container
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Port {
    /// Host IP address that the container's port is mapped to
    #[serde(rename = "IP")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,

    /// Port on the container
    #[serde(rename = "PrivatePort")]
    pub private_port: u16,

    /// Port exposed on the host
    #[serde(rename = "PublicPort")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,

    #[serde(rename = "Type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    // #[serde(with = "::serde_with::As::<::serde_with::NoneAsEmptyString>")]
    pub typ: Option<PortTypeEnum>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum PortTypeEnum {
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "tcp")]
    TCP,
    #[serde(rename = "udp")]
    UDP,
    #[serde(rename = "sctp")]
    SCTP,
}

impl ::std::fmt::Display for PortTypeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            PortTypeEnum::EMPTY => write!(f, ""),
            PortTypeEnum::TCP => write!(f, "{}", "tcp"),
            PortTypeEnum::UDP => write!(f, "{}", "udp"),
            PortTypeEnum::SCTP => write!(f, "{}", "sctp"),
        }
    }
}

impl ::std::str::FromStr for PortTypeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "" => Ok(PortTypeEnum::EMPTY),
            "tcp" => Ok(PortTypeEnum::TCP),
            "udp" => Ok(PortTypeEnum::UDP),
            "sctp" => Ok(PortTypeEnum::SCTP),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for PortTypeEnum {
    fn as_ref(&self) -> &str {
        match self {
            PortTypeEnum::EMPTY => "",
            PortTypeEnum::TCP => "tcp",
            PortTypeEnum::UDP => "udp",
            PortTypeEnum::SCTP => "sctp",
        }
    }
}

/// Configuration for a network endpoint.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EndpointSettings {
    #[serde(rename = "IPAMConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipam_config: Option<EndpointIpamConfig>,

    #[serde(rename = "Links")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<String>>,

    /// MAC address for the endpoint on this network. The network driver might ignore this parameter.
    #[serde(rename = "MacAddress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,

    #[serde(rename = "Aliases")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,

    /// Unique ID of the network.
    #[serde(rename = "NetworkID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,

    /// Unique ID for the service endpoint in a Sandbox.
    #[serde(rename = "EndpointID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,

    /// Gateway address for this network.
    #[serde(rename = "Gateway")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,

    /// IPv4 address.
    #[serde(rename = "IPAddress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,

    /// Mask length of the IPv4 address.
    #[serde(rename = "IPPrefixLen")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_prefix_len: Option<i64>,

    /// IPv6 gateway address.
    #[serde(rename = "IPv6Gateway")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_gateway: Option<String>,

    /// Global IPv6 address.
    #[serde(rename = "GlobalIPv6Address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_ipv6_address: Option<String>,

    /// Mask length of the global IPv6 address.
    #[serde(rename = "GlobalIPv6PrefixLen")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_ipv6_prefix_len: Option<i64>,

    /// DriverOpts is a mapping of driver options and values. These options are passed directly to the driver and are driver specific.
    #[serde(rename = "DriverOpts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver_opts: Option<HashMap<String, String>>,

    /// List of all DNS names an endpoint has on a specific network. This list is based on the container name, network aliases, container short ID, and hostname.  These DNS names are non-fully qualified but can contain several dots. You can get fully qualified DNS names by appending `.<network-name>`. For instance, if container name is `my.ctr` and the network is named `testnet`, `DNSNames` will contain `my.ctr` and the FQDN will be `my.ctr.testnet`.
    #[serde(rename = "DNSNames")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_names: Option<Vec<String>>,
}

/// MountPoint represents a mount point configuration inside the container. This is used for reporting the mountpoints in use by a container.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MountPoint {
    /// The mount type:  - `bind` a mount of a file or directory from the host into the container. - `volume` a docker volume with the given `Name`. - `tmpfs` a `tmpfs`. - `npipe` a named pipe from the host into the container. - `cluster` a Swarm cluster volume
    #[serde(rename = "Type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<MountPointTypeEnum>,

    /// Name is the name reference to the underlying data defined by `Source` e.g., the volume name.
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Source location of the mount.  For volumes, this contains the storage location of the volume (within `/var/lib/docker/volumes/`). For bind-mounts, and `npipe`, this contains the source (host) part of the bind-mount. For `tmpfs` mount points, this field is empty.
    #[serde(rename = "Source")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Destination is the path relative to the container root (`/`) where the `Source` is mounted inside the container.
    #[serde(rename = "Destination")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,

    /// Driver is the volume driver used to create the volume (if it is a volume).
    #[serde(rename = "Driver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    /// Mode is a comma separated list of options supplied by the user when creating the bind/volume mount.  The default is platform-specific (`\"z\"` on Linux, empty on Windows).
    #[serde(rename = "Mode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// Whether the mount is mounted writable (read-write).
    #[serde(rename = "RW")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rw: Option<bool>,

    /// Propagation describes how mounts are propagated from the host into the mount point, and vice-versa. Refer to the [Linux kernel documentation](https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt) for details. This field is not used on Windows.
    #[serde(rename = "Propagation")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub propagation: Option<String>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum MountPointTypeEnum {
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "bind")]
    BIND,
    #[serde(rename = "volume")]
    VOLUME,
    #[serde(rename = "tmpfs")]
    TMPFS,
    #[serde(rename = "npipe")]
    NPIPE,
    #[serde(rename = "cluster")]
    CLUSTER,
}

impl ::std::fmt::Display for MountPointTypeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            MountPointTypeEnum::EMPTY => write!(f, ""),
            MountPointTypeEnum::BIND => write!(f, "{}", "bind"),
            MountPointTypeEnum::VOLUME => write!(f, "{}", "volume"),
            MountPointTypeEnum::TMPFS => write!(f, "{}", "tmpfs"),
            MountPointTypeEnum::NPIPE => write!(f, "{}", "npipe"),
            MountPointTypeEnum::CLUSTER => write!(f, "{}", "cluster"),
        }
    }
}

impl ::std::str::FromStr for MountPointTypeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "" => Ok(MountPointTypeEnum::EMPTY),
            "bind" => Ok(MountPointTypeEnum::BIND),
            "volume" => Ok(MountPointTypeEnum::VOLUME),
            "tmpfs" => Ok(MountPointTypeEnum::TMPFS),
            "npipe" => Ok(MountPointTypeEnum::NPIPE),
            "cluster" => Ok(MountPointTypeEnum::CLUSTER),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for MountPointTypeEnum {
    fn as_ref(&self) -> &str {
        match self {
            MountPointTypeEnum::EMPTY => "",
            MountPointTypeEnum::BIND => "bind",
            MountPointTypeEnum::VOLUME => "volume",
            MountPointTypeEnum::TMPFS => "tmpfs",
            MountPointTypeEnum::NPIPE => "npipe",
            MountPointTypeEnum::CLUSTER => "cluster",
        }
    }
}

/// EndpointIPAMConfig represents an endpoint's IPAM configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EndpointIpamConfig {
    #[serde(rename = "IPv4Address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_address: Option<String>,

    #[serde(rename = "IPv6Address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_address: Option<String>,

    #[serde(rename = "LinkLocalIPs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_local_i_ps: Option<Vec<String>>,
}
