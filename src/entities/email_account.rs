use super::user_auth_data;
use sea_orm::prelude::*;
use sea_orm::ActiveValue::Set;
use sea_orm::QuerySelect;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "user_email_account", schema_name = "ame-auth")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(indexed, unique)]
    pub email: String,
    pub password: String,
    #[sea_orm(indexed, unique)]
    pub user_id: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "user_auth_data::Entity",
        from = "Column::UserId",
        to = "user_auth_data::Column::Id"
    )]
    UserAuthData,
}

impl Related<user_auth_data::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::UserAuthData.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub async fn create_account(
        db: &impl ConnectionTrait,
        email: &str,
        password: &str,
        user_id: i32,
    ) -> Result<Model, DbErr> {
        let account = ActiveModel {
            email: Set(email.to_owned()),
            password: Set(password.to_owned()),
            user_id: Set(user_id),
            ..Default::default()
        };
        account.insert(db).await
    }
    pub async fn find_by_email(
        db: &impl ConnectionTrait,
        email: &str,
    ) -> Result<Option<Model>, DbErr> {
        Entity::find().filter(Column::Email.eq(email)).one(db).await
    }
    pub async fn find_auth_data_from_email(
        db: &impl ConnectionTrait,
        email: &str,
    ) -> Result<Option<(Model, user_auth_data::Model)>, DbErr> {
        let result = Entity::find()
            .filter(Column::Email.eq(email))
            .limit(1)
            .find_also_related(user_auth_data::Entity)
            .one(db)
            .await?;
        match result {
            Some((a, Some(b))) => Ok(Some((a, b))),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Entity;
    use sea_orm::{DbBackend, Schema};

    #[test]
    fn create_table_sql() {
        let db_postgres = DbBackend::Postgres;
        let schema = Schema::new(db_postgres);
        let _1 = db_postgres.build(&schema.create_table_from_entity(Entity));
    }
}
