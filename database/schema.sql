CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username      TEXT NOT NULL,
    hash          TEXT NOT NULL,
    cash          NUMERIC NOT NULL DEFAULT 10000.00
);

CREATE TABLE exchange (
    id            INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    symbol        TEXT NOT NULL,
    name          TEXT NOT NULL,
    shares        INTEGER NOT NULL,
    activity      TEXT NOT NULL,
    at_price      NUMERIC NOT NULL,
    total_price   NUMERIC NOT NULL,
    epoch_time    INTEGER NOT NULL,
    user_id       INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE portfolio (
    id            INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    symbol        TEXT NOT NULL,
    name          TEXT NOT NULL,
    shares        INTEGER NOT NULL,
    user_id       INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE UNIQUE INDEX username ON users (username);