use axum::response::sse::{Event, Sse};
use futures::Stream;
use serde_json::Value;
use std::convert::Infallible;
use tokio::sync::broadcast::Sender;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

pub fn stream(tx: Sender<Value>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = BroadcastStream::new(tx.subscribe());
    let s = rx
        .filter_map(|row| row.ok())
        .map(|row| Ok(Event::default().event("audit").data(row.to_string())));
    Sse::new(s)
}
