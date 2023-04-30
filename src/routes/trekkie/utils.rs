use crate::routes::ServerError;
use crate::DbPool;

use lofi::correlate::correlate_trekkie_run;
use tlms::locations::gps::GpsPoint;
use tlms::locations::InsertTransmissionLocationRaw;
use tlms::telegrams::r09::R09SaveTelegram;
use tlms::trekkie::TrekkieRun;

use actix_web::web;
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
use log::error;

/// Private function that does the dirty correlation work.
pub async fn correlate_single_run(
    run: TrekkieRun,
    pool: &web::Data<DbPool>,
    corr_window: i64,
) -> Result<Vec<InsertTransmissionLocationRaw>, ServerError> {
    // get connection from the pool
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    use tlms::schema::gps_points::dsl::gps_points;
    use tlms::schema::gps_points::trekkie_run;
    let queried_gps: Vec<GpsPoint> = match gps_points
        .filter(trekkie_run.eq(run.id))
        .load(&mut database_connection)
    {
        Ok(points) => points,
        Err(e) => {
            error!(
                "while fetching gps points for run id {id}: {e}",
                id = run.id
            );
            return Err(ServerError::InternalError);
        }
    };

    // query r09 telegrams matching the timeframe of the run
    use tlms::schema::r09_telegrams::dsl::r09_telegrams;

    use tlms::schema::r09_telegrams::line as telegram_line;
    use tlms::schema::r09_telegrams::run_number as telegram_run;
    use tlms::schema::r09_telegrams::time as telegram_time;
    let telegrams: Vec<R09SaveTelegram> = match r09_telegrams
        .filter(telegram_time.ge(run.start_time))
        .filter(telegram_time.le(run.end_time))
        .filter(telegram_line.eq(run.line))
        .filter(telegram_run.eq(run.run))
        .load::<R09SaveTelegram>(&mut database_connection)
    {
        Ok(t) => t,
        Err(e) => {
            error!(
                "While trying to query the telegrams matching {run}: {e}",
                run = run.id
            );
            return Err(ServerError::InternalError);
        }
    };

    // corrrelate
    let locs = match correlate_trekkie_run(&telegrams, queried_gps, corr_window, run.id, run.owner)
    {
        Ok(l) => l,
        Err(e) => {
            error!(
                "error while correlating data {} with error {:?}",
                &run.id, &e
            );
            return Err(ServerError::InternalError);
        }
    };
    // Update correlated flag in the trekkie_runs db
    use tlms::schema::trekkie_runs::correlated as trekkie_corr_flag;
    use tlms::schema::trekkie_runs::dsl::trekkie_runs;
    use tlms::schema::trekkie_runs::id as run_id;
    match diesel::update(trekkie_runs)
        .filter(run_id.eq(run.id))
        .set(trekkie_corr_flag.eq(true))
        .execute(&mut database_connection)
    {
        Ok(ok) => ok,
        Err(e) => {
            error!("while trying to set `correlated` flag in trekkie_runs: {e:?}");
            return Err(ServerError::InternalError);
        }
    };

    Ok(locs)
}
