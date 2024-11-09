use super::email_account;
use chrono::NaiveDateTime;
use sea_orm::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "user_auth_data", schema_name = "ame-auth")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(default_expr = "Expr::current_timestamp()")]
    pub created_at: NaiveDateTime,
    #[sea_orm(default_expr = "Expr::current_timestamp()")]
    pub updated_at: NaiveDateTime,
    #[sea_orm(nullable)]
    pub email: Option<String>,
    #[sea_orm(nullable)]
    pub username: Option<String>,
    #[sea_orm(default_value = false)]
    pub is_banned: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_one = "email_account::Entity")]
    EmailAccount,
}

impl Related<email_account::Entity> for Model {
    fn to() -> RelationDef {
        Relation::EmailAccount.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub async fn create(db: &impl ConnectionTrait) -> Result<Self, DbErr> {
        let active = ActiveModel {
            ..Default::default()
        };
        active.insert(db).await
    }
}
