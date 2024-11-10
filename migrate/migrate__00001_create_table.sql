CREATE SCHEMA IF NOT EXISTS "ame-auth";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP TABLE IF EXISTS "ame-auth"."user_email_account";
CREATE TABLE "ame-auth"."user_auth_data"
(
    "id"         serial                      NOT NULL PRIMARY KEY,
    "created_at" timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "email"      varchar,
    "username"   varchar,
    "is_banned"  bool                        NOT NULL DEFAULT FALSE
);

DROP TABLE IF EXISTS "ame-auth"."user_email_account";
CREATE TABLE "ame-auth"."user_email_account"
(
    "id"       serial  NOT NULL PRIMARY KEY,
    "email"    varchar NOT NULL UNIQUE,
    "password" varchar NOT NULL,
    "user_id"  integer NOT NULL UNIQUE,
    CONSTRAINT "fk-user_email_account-user_id"
        FOREIGN KEY ("user_id")
            REFERENCES "ame-auth"."user_auth_data" ("id")
            ON DELETE CASCADE
);

DROP TABLE IF EXISTS "ame-auth"."email_verifying";
CREATE TABLE "ame-auth"."email_verifying"
(
    "email"    varchar                     NOT NULL UNIQUE,
    "auth_key" uuid                        NOT NULL DEFAULT GEN_RANDOM_UUID() PRIMARY KEY,
    "password" varchar                     NOT NULL,
    "send_at"  timestamp without time zone NOT NULL
);