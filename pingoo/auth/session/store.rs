use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub picture: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

pub struct SessionStore {
    sessions: DashMap<String, Session>,
    oauth_states: DashMap<String, (String, Instant)>,
    session_duration: Duration,
    state_duration: Duration,
}

impl SessionStore {
    pub fn new(session_duration: Duration) -> Self {
        Self {
            sessions: DashMap::new(),
            oauth_states: DashMap::new(),
            session_duration,
            state_duration: Duration::from_secs(600),
        }
    }

    pub fn create(&self, id: String, user_id: String, email: String, name: String, picture: Option<String>) -> Session {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::from_std(self.session_duration).unwrap();

        let session = Session {
            id: id.clone(),
            user_id,
            email,
            name,
            picture,
            created_at: now,
            expires_at,
            last_seen: now,
        };

        self.sessions.insert(id, session.clone());
        println!("Session store now has {} sessions", self.sessions.len());
        session
    }

    pub fn get(&self, id: &str) -> Option<Session> {
        self.sessions.get(id).map(|s| s.value().clone())
    }

    pub fn delete(&self, id: &str) {
        self.sessions.remove(id);
    }

    pub fn update_last_seen(&self, id: &str) {
        if let Some(mut session) = self.sessions.get_mut(id) {
            session.last_seen = Utc::now();
        }
    }

    pub fn cleanup_expired(&self) -> usize {
        let now = Utc::now();
        let to_delete: Vec<String> = self
            .sessions
            .iter()
            .filter(|entry| entry.value().expires_at < now)
            .map(|entry| entry.key().clone())
            .collect();

        let count = to_delete.len();
        for id in to_delete {
            self.sessions.remove(&id);
        }
        count
    }

    pub fn store_oauth_state(&self, state: String, original_url: String) {
        self.oauth_states.insert(state, (original_url, Instant::now()));
    }

    pub fn get_oauth_state(&self, state: &str) -> Option<String> {
        self.oauth_states.get(state).and_then(|entry| {
            let (url, created_at) = entry.value();
            if created_at.elapsed() < self.state_duration {
                Some(url.clone())
            } else {
                None
            }
        })
    }

    pub fn delete_oauth_state(&self, state: &str) {
        self.oauth_states.remove(state);
    }

    pub fn cleanup_expired_states(&self) -> usize {
        let now = Instant::now();
        let to_delete: Vec<String> = self
            .oauth_states
            .iter()
            .filter(|entry| now.duration_since(entry.value().1) >= self.state_duration)
            .map(|entry| entry.key().clone())
            .collect();

        let count = to_delete.len();
        for state in to_delete {
            self.oauth_states.remove(&state);
        }
        count
    }
}
