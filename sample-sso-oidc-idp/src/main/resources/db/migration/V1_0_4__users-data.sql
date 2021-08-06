INSERT INTO users (username, password, enabled)
VALUES ('admin', '{noop}123456', 1);

INSERT INTO authorities (username, authority)
VALUES ('admin', 'ROLE_USER');
