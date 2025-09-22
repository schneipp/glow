use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand_core::OsRng;

use axum::{
    Json, Router,
    extract::{
        Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    routing::get,
};
use axum_extra::TypedHeader;
use axum_extra::extract::cookie::{Cookie, CookieJar};
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

use axum::response::IntoResponse;
use axum::routing::post;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tokio::time::interval;
type RoomId = String;

#[derive(Clone)]
struct AppState {
    //Arc for shared ownership, DashMap for concurrent access
    // RoomId maps to a broadcast channel sender
    rooms: Arc<DashMap<RoomId, broadcast::Sender<String>>>,
    users: Arc<DashMap<String, String>>, // username -> password_hash
    jwt: JwtKeys,
}
#[derive(Clone)]
struct JwtKeys {
    enc: EncodingKey,
    dec: DecodingKey,
}
impl JwtKeys {
    fn new(secret: &[u8]) -> Self {
        Self {
            enc: EncodingKey::from_secret(secret),
            dec: DecodingKey::from_secret(secret),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String, // username? maybe user id later
    exp: usize,
    iat: usize,
}

#[derive(Serialize, Deserialize)]
struct ChatEvent {
    room: String,
    username: String,
    text: String,
    ts: i64, // unix seconds
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let state = AppState {
        rooms: Arc::new(DashMap::new()),
        users: Arc::new(DashMap::new()),
        jwt: JwtKeys::new(b"dev-secret-change-me"), // TODO: ENV in prod
    };

    let app = Router::new()
        .route("/api/register", post(register))
        .route("/api/login", post(login))
        .route("/api/channels", get(list_channels))
        .route("/ws/{room_id}", get(ws_handler))
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();

    print_banner();

    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

async fn ws_handler(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
    jar: CookieJar,
    auth: Option<TypedHeader<Authorization<Bearer>>>,
    ws: WebSocketUpgrade,
) -> impl axum::response::IntoResponse {
    // authenticate before upgrading
    let Ok((_jar, username)) = user_from_req(jar, auth, State(state.clone())).await else {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    };

    ws.on_upgrade(move |socket| handle_socket(socket, state, room_id, username))
}
async fn handle_socket(socket: WebSocket, state: AppState, room_id: String, username: String) {
    // get or create the room broadcaster
    let room_id_clone = room_id.clone();
    let tx = state
        .rooms
        .entry(room_id.clone())
        .or_insert_with(|| broadcast::channel::<String>(1024).0)
        .clone();

    // subscribe for inbound fanout
    let mut rx = tx.subscribe();

    // outbound queue: anything the recv task (or others) want to send to this socket
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(256);
    let heartbeat_tx = out_tx.clone();
    let ping_task = tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(20));
        loop {
            tick.tick().await;
            // empty payload ping is fine, but 69 is what i define in the GLOW RFC TRUST ME BRO
            if heartbeat_tx
                .send(Message::Ping(vec![69].into()))
                .await
                .is_err()
            {
                break; // socket gone, please die 
            }
        }
    });
    // split socket, sorcerer style
    // we need to split the socket so we can send and receive at the same time
    let (mut ws_sender, mut ws_receiver) = socket.split();

    // task: forward room broadcasts and anything in out_rx -> this socket
    // if either channel closes, we close the socket
    // if sending to the socket fails, we close the socket
    let send_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                // room fanout (String -> Text)
                Ok(msg) = rx.recv() => {
                    if ws_sender.send(Message::Text(msg.into())).await.is_err() {
                        break;
                    }
                }
                // explicit outbound messages (including Pong)
                Some(msg) = out_rx.recv() => {
                    if ws_sender.send(msg).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // task: read this socket -> publish to room or queue control replies
    let recv_task = {
        let tx = tx.clone();
        tokio::spawn(async move {
            while let Some(Ok(msg)) = ws_receiver.next().await {
                match msg {
                    Message::Text(text_bytes) => {
                        let ev = ChatEvent {
                            room: room_id.clone(),
                            username: username.clone(),
                            text: text_bytes.to_string(),
                            ts: OffsetDateTime::now_utc().unix_timestamp(),
                        };
                        let json = serde_json::to_string(&ev).unwrap();
                        let _ = tx.send(json);
                    }
                    /*
                       Message::Text(text_bytes) => {
                           let text: String = text_bytes.as_str().into();
                           let _ = tx.send(text); // fan out to the room
                       }

                    */
                    Message::Ping(p) => {
                        // enqueue Pong via the outbound queue (so we don't need the sink here)
                        let _ = out_tx.send(Message::Pong(p)).await;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        })
    };

    let _ = tokio::join!(send_task, recv_task, ping_task);

    // cleanup: remove empty room
    if tx.receiver_count() == 0 {
        state.rooms.remove(&room_id_clone);
    }
}

fn hash_password(plain: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng); // 0.5 API
    let hash = Argon2::default()
        .hash_password(plain.as_bytes(), &salt)?
        .to_string();
    Ok(hash)
}

fn verify_password(hash: &str, plain: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok()
}

async fn user_from_req(
    jar: CookieJar,
    auth: Option<TypedHeader<Authorization<Bearer>>>,
    State(state): State<AppState>,
) -> Result<(CookieJar, String), (StatusCode, &'static str)> {
    // Try Authorization header first
    let token_opt = auth
        .as_ref()
        .map(|TypedHeader(Authorization(bearer))| bearer.token().to_string())
        .or_else(|| jar.get("chat_token").map(|c| c.value().to_string()));

    let Some(token) = token_opt else {
        return Err((StatusCode::UNAUTHORIZED, "missing auth token"));
    };

    let data = decode::<Claims>(&token, &state.jwt.dec, &Validation::new(Algorithm::HS256))
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token"))?;

    Ok((jar, data.claims.sub))
}

#[derive(Deserialize)]
struct AuthReq {
    username: String,
    password: String,
}
#[derive(Serialize)]
struct LoginRes {
    token: String,
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<AuthReq>,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    if req.username.trim().is_empty() || req.password.len() < 6 {
        return Err((StatusCode::BAD_REQUEST, "invalid username or password"));
    }
    if state.users.contains_key(&req.username) {
        return Err((StatusCode::CONFLICT, "user exists"));
    }
    let hash = hash_password(&req.password)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "hash error"))?;
    state.users.insert(req.username, hash);
    Ok(StatusCode::CREATED)
}

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<AuthReq>,
) -> Result<(CookieJar, Json<LoginRes>), (StatusCode, &'static str)> {
    let Some(stored) = state.users.get(&req.username) else {
        return Err((StatusCode::UNAUTHORIZED, "invalid credentials"));
    };
    if !verify_password(&stored, &req.password) {
        return Err((StatusCode::UNAUTHORIZED, "invalid credentials"));
    }

    let now = OffsetDateTime::now_utc().unix_timestamp() as usize;
    let exp = now + 60 * 60 * 24 * 7; // 7 days
    let claims = Claims {
        sub: req.username.clone(),
        iat: now,
        exp,
    };
    let token = encode(&Header::new(Algorithm::HS256), &claims, &state.jwt.enc)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "token error"))?;

    let cookie = Cookie::build(("chat_token", token.clone()))
        .http_only(true)
        .path("/")
        .max_age(time::Duration::days(7))
        .build();

    Ok((jar.add(cookie), Json(LoginRes { token })))
}

#[derive(Serialize)]
struct ChannelsRes {
    channels: Vec<String>,
}

async fn list_channels(
    jar: CookieJar,
    auth: Option<TypedHeader<Authorization<Bearer>>>,
    State(state): State<AppState>,
) -> Result<Json<ChannelsRes>, (StatusCode, &'static str)> {
    // authenticate (reuses your helper)
    let (_jar, _username) = user_from_req(jar, auth, State(state.clone())).await?;

    // list channels
    let chans: Vec<String> = state.rooms.iter().map(|e| e.key().clone()).collect();
    Ok(Json(ChannelsRes { channels: chans }))
}


fn print_banner() {
    println!("  ██████╗ ██╗      ██████╗ ██╗    ██╗");
    println!(" ██╔════╝ ██║     ██╔═══██╗██║    ██║");
    println!(" ██║  ███╗██║     ██║   ██║██║ █╗ ██║");
    println!(" ██║   ██║██║     ██║   ██║██║███╗██║");
    println!(" ╚██████╔╝███████╗╚██████╔╝╚███╔███╔╝");
    println!("  ╚═════╝ ╚══════╝ ╚═════╝  ╚══╝╚══╝ ");
    println!("   ..i am going to build my own chat server");
    println!("       WITH BEER POT AND HOOKERS");
}
