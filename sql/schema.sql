CREATE TABLE IF NOT EXISTS captured_packets (
    id SERIAL PRIMARY KEY,
    time TEXT,
    source TEXT,
    destination TEXT,
    protocol TEXT,
    length INTEGER,
    info TEXT,
    is_mine BOOLEAN,
    is_broadcast_or_multicast BOOLEAN
);
