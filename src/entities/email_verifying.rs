use chrono::NaiveDateTime;
use sea_orm::prelude::*;
use sea_orm::sea_query::{OnConflict, PgFunc};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "email_verifying", schema_name = "ame-auth")]
pub struct Model {
    #[sea_orm(indexed, unique)]
    pub email: String,
    #[sea_orm(
        primary_key,
        column_type = "Uuid",
        auto_increment = false,
        default_expr = "PgFunc::gen_random_uuid()"
    )]
    pub auth_key: Uuid,
    pub password: String,
    pub send_at: NaiveDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub async fn create_or_update(
        db: &impl ConnectionTrait,
        email: &str,
        password: &str,
    ) -> Result<Self, DbErr> {
        let auth_key = Uuid::new_v4();
        let send_at = chrono::Utc::now().naive_utc();
        let model = Model {
            email: email.to_owned(),
            auth_key,
            send_at,
            password: password.to_owned(),
        };
        let active: ActiveModel = model.clone().into();
        Entity::insert(active)
            .on_conflict(
                OnConflict::column(Column::Email)
                    .update_columns([Column::AuthKey, Column::SendAt, Column::Password])
                    .to_owned(),
            )
            .exec(db)
            .await?;
        Ok(model)
    }
    pub async fn find_by_email(
        db: &impl ConnectionTrait,
        email: &str,
    ) -> Result<Option<Self>, DbErr> {
        Entity::find().filter(Column::Email.eq(email)).one(db).await
    }
    pub async fn find_by_auth_id(
        db: &impl ConnectionTrait,
        auth_id: Uuid,
    ) -> Result<Option<Self>, DbErr> {
        Entity::find()
            .filter(Column::AuthKey.eq(auth_id))
            .one(db)
            .await
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
