use crate::BackendEvent;
use serde::{Deserialize, Serialize};
use std::fmt;
use tokio::sync::broadcast;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChangeCursor(pub u64);

pub struct EventSubscription {
    pub(crate) receiver: broadcast::Receiver<BackendEvent>,
}

impl EventSubscription {
    pub async fn recv(&mut self) -> Result<BackendEvent, EventRecvError> {
        self.receiver.recv().await.map_err(|error| match error {
            broadcast::error::RecvError::Closed => EventRecvError::Closed,
            broadcast::error::RecvError::Lagged(count) => EventRecvError::Lagged(count),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventRecvError {
    Closed,
    Lagged(u64),
}

impl fmt::Display for EventRecvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("event stream closed"),
            Self::Lagged(count) => write!(formatter, "event stream lagged by {count} changes"),
        }
    }
}

impl std::error::Error for EventRecvError {}
