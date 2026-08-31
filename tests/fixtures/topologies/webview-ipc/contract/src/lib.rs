#![forbid(unsafe_code)]

use std::{
    fmt,
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RequestId(String);

impl RequestId {
    pub fn checked(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        let bytes = value.as_bytes();
        let valid = !bytes.is_empty()
            && bytes.len() <= 128
            && bytes[0].is_ascii_lowercase()
            && bytes[bytes.len() - 1] != b'-'
            && !bytes.windows(2).any(|pair| pair == b"--")
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
        if valid {
            Ok(Self(value))
        } else {
            Err(ContractError::InvalidRequestId)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunCommand {
    request_id: RequestId,
    input: String,
}

impl RunCommand {
    pub fn checked(request_id: RequestId, input: impl Into<String>) -> Result<Self, ContractError> {
        let input = input.into();
        if input.len() > 4096 {
            return Err(ContractError::InputTooLarge);
        }
        Ok(Self { request_id, input })
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn input(&self) -> &str {
        &self.input
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunCompleted {
    request_id: RequestId,
    output: String,
}

impl RunCompleted {
    pub fn from_backend(request_id: RequestId, output: String) -> Self {
        Self { request_id, output }
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn output(&self) -> &str {
        &self.output
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractError {
    InvalidRequestId,
    InputTooLarge,
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestId => formatter.write_str("invalid request id"),
            Self::InputTooLarge => formatter.write_str("IPC input exceeds 4096 bytes"),
        }
    }
}

impl std::error::Error for ContractError {}

#[derive(Clone, Debug)]
pub struct EventSender(SyncSender<RunCompleted>);

#[derive(Debug)]
pub struct EventReceiver(Receiver<RunCompleted>);

pub fn bounded_event_channel(
    capacity: usize,
) -> Result<(EventSender, EventReceiver), ChannelError> {
    if !(1..=256).contains(&capacity) {
        return Err(ChannelError::InvalidCapacity);
    }
    let (sender, receiver) = mpsc::sync_channel(capacity);
    Ok((EventSender(sender), EventReceiver(receiver)))
}

impl EventSender {
    pub fn try_publish(&self, event: RunCompleted) -> Result<(), ChannelError> {
        self.0.try_send(event).map_err(|error| match error {
            TrySendError::Full(_) => ChannelError::Full,
            TrySendError::Disconnected(_) => ChannelError::Closed,
        })
    }
}

impl EventReceiver {
    pub fn try_receive(&self) -> Result<RunCompleted, ChannelError> {
        self.0.try_recv().map_err(|error| match error {
            TryRecvError::Empty => ChannelError::Empty,
            TryRecvError::Disconnected => ChannelError::Closed,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelError {
    InvalidCapacity,
    Full,
    Empty,
    Closed,
}

impl fmt::Display for ChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapacity => formatter.write_str("IPC channel capacity must be 1..=256"),
            Self::Full => formatter.write_str("IPC channel is full"),
            Self::Empty => formatter.write_str("IPC channel is empty"),
            Self::Closed => formatter.write_str("IPC channel is closed"),
        }
    }
}

impl std::error::Error for ChannelError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ids_and_payloads_are_bounded() {
        assert!(RequestId::checked("request-42").is_ok());
        assert!(RequestId::checked("Request-42").is_err());
        assert!(
            RunCommand::checked(RequestId::checked("request-42").unwrap(), "x".repeat(4096))
                .is_ok()
        );
        assert!(
            RunCommand::checked(RequestId::checked("request-42").unwrap(), "x".repeat(4097))
                .is_err()
        );
    }

    #[test]
    fn event_channel_is_bounded_nonblocking_and_closed() {
        assert!(bounded_event_channel(0).is_err());
        assert!(bounded_event_channel(257).is_err());
        let (sender, receiver) = bounded_event_channel(1).unwrap();
        let event =
            RunCompleted::from_backend(RequestId::checked("request-42").unwrap(), "done".into());
        sender.try_publish(event.clone()).unwrap();
        assert_eq!(sender.try_publish(event), Err(ChannelError::Full));
        assert_eq!(receiver.try_receive().unwrap().output(), "done");
        assert_eq!(receiver.try_receive(), Err(ChannelError::Empty));
        drop(receiver);
        assert_eq!(
            sender.try_publish(RunCompleted::from_backend(
                RequestId::checked("request-43").unwrap(),
                "done".into(),
            )),
            Err(ChannelError::Closed)
        );
    }
}
