#![allow(non_snake_case)]
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct LoginData {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub token: String,
    pub refreshToken: String,
    pub unitTraining: UnitTraining,
    pub roles: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct UnitTraining {
    id: String,
    unitTrainingId: String,
    name: String,
    shortName: String,
    description: Option<String>,
    orderToDisplay: Option<Vec<usize>>,
}

impl LoginData {
    pub fn empty() -> Self {
        Self {
            id: String::new(),
            username: String::new(),
            token: String::new(),
            refreshToken: String::new(),
            email: None,
            unitTraining: UnitTraining {
                id: String::new(),
                unitTrainingId: String::new(),
                name: String::new(),
                shortName: String::new(),
                description: None,
                orderToDisplay: None,
            },
            roles: Vec::new(),
        }
    }

    pub fn set_token(&mut self, token: &str) {
        self.token.clear();
        self.token = token.to_string();
    }

    pub fn from(&mut self, other: LoginData) {
        self.id = other.id;
        self.username = other.username;
        self.token = other.token;
        self.refreshToken = other.refreshToken;
        self.email = other.email;
        self.unitTraining = other.unitTraining;
        self.roles = other.roles;
    }
}
