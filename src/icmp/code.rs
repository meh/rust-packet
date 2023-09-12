//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

/// Codes for Destination Unreachable packets.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum DestinationUnreachable {
    ///
    DestinationNetworkUnreachable,

    ///
    DestinationHostUnreachable,

    ///
    DestinationProtocolUnreachable,

    ///
    DestinationPortUnreachable,

    ///
    FragmentationRequired,

    ///
    SourceRouteFailed,

    ///
    DestinationNetworkUnknown,

    ///
    DestinationHostUnknown,

    ///
    SourceHostIsolated,

    ///
    NetworkAdministrativelyProhibited,

    ///
    HostAdministrativelyProhibited,

    ///
    NetworkUnreachableForTos,

    ///
    HostUnreachableForTos,

    ///
    CommunicationAdministrativelyProhibited,

    ///
    HostPrecedenceViolation,

    ///
    PrecedentCutoffInEffect,

    ///
    Unknown(u8),
}

/// Codes for Redirect Message packets.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum RedirectMessage {
    ///
    RedirectDatagramForNetwork,

    ///
    RedirectDatagramForHost,

    ///
    RedirectDatagramForTosAndNetwork,

    ///
    RedirectDatagramForTosAndHost,

    ///
    Unknown(u8),
}

/// Codes for Parameter Problem packets.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum ParameterProblem {
    ///
    PointerIndicatesError,

    ///
    MissingRequiredData,

    ///
    BadLength,

    ///
    Unknown(u8),
}

impl From<u8> for DestinationUnreachable {
    fn from(value: u8) -> Self {
        use self::DestinationUnreachable::*;

        match value {
            0 => DestinationNetworkUnreachable,
            1 => DestinationHostUnreachable,
            2 => DestinationProtocolUnreachable,
            3 => DestinationPortUnreachable,
            4 => FragmentationRequired,
            5 => SourceRouteFailed,
            6 => DestinationNetworkUnknown,
            7 => DestinationHostUnknown,
            8 => SourceHostIsolated,
            9 => NetworkAdministrativelyProhibited,
            10 => HostAdministrativelyProhibited,
            11 => NetworkUnreachableForTos,
            12 => HostUnreachableForTos,
            13 => CommunicationAdministrativelyProhibited,
            14 => HostPrecedenceViolation,
            15 => PrecedentCutoffInEffect,
            v => Unknown(v),
        }
    }
}

impl From<DestinationUnreachable> for u8 {
    fn from(val: DestinationUnreachable) -> Self {
        use self::DestinationUnreachable::*;

        match val {
            DestinationNetworkUnreachable => 0,
            DestinationHostUnreachable => 1,
            DestinationProtocolUnreachable => 2,
            DestinationPortUnreachable => 3,
            FragmentationRequired => 4,
            SourceRouteFailed => 5,
            DestinationNetworkUnknown => 6,
            DestinationHostUnknown => 7,
            SourceHostIsolated => 8,
            NetworkAdministrativelyProhibited => 9,
            HostAdministrativelyProhibited => 10,
            NetworkUnreachableForTos => 11,
            HostUnreachableForTos => 12,
            CommunicationAdministrativelyProhibited => 13,
            HostPrecedenceViolation => 14,
            PrecedentCutoffInEffect => 15,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for RedirectMessage {
    fn from(value: u8) -> Self {
        use self::RedirectMessage::*;

        match value {
            0 => RedirectDatagramForNetwork,
            1 => RedirectDatagramForHost,
            2 => RedirectDatagramForTosAndNetwork,
            3 => RedirectDatagramForTosAndHost,
            v => Unknown(v),
        }
    }
}

impl From<RedirectMessage> for u8 {
    fn from(val: RedirectMessage) -> Self {
        use self::RedirectMessage::*;

        match val {
            RedirectDatagramForNetwork => 0,
            RedirectDatagramForHost => 1,
            RedirectDatagramForTosAndNetwork => 2,
            RedirectDatagramForTosAndHost => 3,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for ParameterProblem {
    fn from(value: u8) -> Self {
        use self::ParameterProblem::*;

        match value {
            0 => PointerIndicatesError,
            1 => MissingRequiredData,
            2 => BadLength,
            v => Unknown(v),
        }
    }
}

impl From<ParameterProblem> for u8 {
    fn from(val: ParameterProblem) -> Self {
        use self::ParameterProblem::*;

        match val {
            PointerIndicatesError => 0,
            MissingRequiredData => 1,
            BadLength => 2,
            Unknown(v) => v,
        }
    }
}
