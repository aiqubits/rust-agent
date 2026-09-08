use rust_agent_session::{
    ExistingSessionReservation, NewSessionReservation, SessionEventCursor, SessionIndexCursor,
    SessionIndexOrderingKey, SessionProjectionCursor,
};

fn inspect_index_cursor(cursor: SessionIndexCursor) {
    let _ = cursor.schema_version;
}

fn inspect_index_ordering_key(key: SessionIndexOrderingKey) {
    let _ = key.creation_commit_order;
}

fn inspect_event_cursor(cursor: SessionEventCursor) {
    let _ = cursor.backend;
}

fn inspect_projection_cursor(cursor: SessionProjectionCursor) {
    let _ = cursor.session_id;
}

fn inspect_new_reservation(reservation: NewSessionReservation) {
    let _ = reservation.allocation;
}

fn inspect_existing_reservation(reservation: ExistingSessionReservation) {
    let _ = reservation.reservation;
}

fn main() {}
