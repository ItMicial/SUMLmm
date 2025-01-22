BEGIN;
CREATE TABLE Users (
    id INT AUTOINCREMENT,
    username TEXT,
    passwd_hash TEXT,
    PRIMARY KEY (id)
);
CREATE TABLE Sites (
    id INT AUTOINCREMENT,
    site TEXT,
    PRIMARY KEY (id)
);
CREATE TABLE UsersSites (
    userId INT, 
    siteId INT,
    FOREIGN KEY (userId) REFERENCES Users(id),
    FOREIGN KEY (siteId) REFERENCES Sites(id),
    PRIMARY KEY (userId, siteId)
);
CREATE TABLE PhishingCheckResult (
    siteId INT,
    checkDate INT,
    result INT,
    FOREIGN KEY (siteId) REFERENCES Sites(id),
    PRIMARY KEY (siteId, checkDate)
);
COMMIT;