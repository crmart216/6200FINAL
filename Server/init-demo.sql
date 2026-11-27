\getenv app_password CHAT_APP_PASSWORD
CREATE ROLE chat_demo_app LOGIN PASSWORD :'app_password';
CREATE DATABASE chat_demo OWNER chat_demo_app TEMPLATE template0;
\connect chat_demo
GRANT USAGE, CREATE ON SCHEMA public TO chat_demo_app;