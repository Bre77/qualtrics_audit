import json
import logging
import requests
from datetime import datetime, timedelta
from urllib.parse import urlencode

import import_declare_test
from solnlib import conf_manager, log
from solnlib.modular_input import checkpointer
from splunklib import modularinput as smi


ADDON_NAME = "qualtrics_audit"


def logger_for_input(input_name: str) -> logging.Logger:
    return log.Logs().get_logger(f"{ADDON_NAME.lower()}_{input_name}")


def get_account_config(session_key: str, account_name: str):
    cfm = conf_manager.ConfManager(
        session_key,
        ADDON_NAME,
        realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-qualtrics_audit_account",
    )
    account_conf_file = cfm.get_conf("qualtrics_audit_account")
    account_config = account_conf_file.get(account_name)
    return {
        "api_key": account_config.get("api_key"),
        "domain": account_config.get("domain", "yul1.qualtrics.com"),
    }


def get_checkpoint_key(input_name: str, account_name: str) -> str:
    """Generate a unique checkpoint key for this input and account combination."""
    return f"{input_name}_{account_name}_last_end_date"


def get_last_end_date(ckpt: checkpointer.KVStoreCheckpointer, key: str) -> datetime:
    """Get the last end date from checkpoint, or default to 90 days ago."""
    try:
        checkpoint_data = ckpt.get(key)
        if checkpoint_data and "last_end_date" in checkpoint_data:
            return datetime.fromisoformat(checkpoint_data["last_end_date"])
    except Exception:
        pass

    # Default to 90 days ago if no checkpoint exists
    return datetime.utcnow() - timedelta(days=90)


def save_checkpoint(
    ckpt: checkpointer.KVStoreCheckpointer, key: str, end_date: datetime
):
    """Save the end date from this run as the start date for the next run."""
    checkpoint_data = {
        "last_end_date": end_date.isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }
    ckpt.update(key, checkpoint_data)


def get_data_from_api(
    logger: logging.Logger,
    api_key: str,
    domain: str,
    start_date: datetime,
    end_date: datetime,
):
    """Fetch audit log data from Qualtrics API with date range filtering."""
    session = requests.Session()
    session.headers.update({"X-API-TOKEN": api_key})

    # Build query parameters
    params = {
        "pageSize": 1000,
        "startDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "endDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }

    base_url = f"https://{domain}/API/v3/logs"
    url = f"{base_url}?{urlencode(params)}"

    results = []

    logger.info(f"Fetching data from {start_date} to {end_date}")

    while url:
        logger.debug(f"Fetching page: {url}")
        resp = session.get(url)

        if resp.status_code == 200:
            data = resp.json()
            elements = data.get("result", {}).get("elements", [])
            results.extend(elements)

            # Get next page URL
            url = data.get("result", {}).get("nextPage")

            logger.info(
                f"Fetched {len(elements)} records from current page. Total so far: {len(results)}"
            )

        else:
            logger.error(
                f"Failed to fetch data from API: {resp.status_code} - {resp.text}"
            )
            break

    logger.info(f"Total records fetched: {len(results)}")
    return results


def validate_input(definition: smi.ValidationDefinition):
    return


def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter):
    # inputs.inputs is a Python dictionary object like:
    # {
    #   "qualtrics_audit://<input_name>": {
    #     "account": "<account_name>",
    #     "disabled": "0",
    #     "host": "$decideOnStartup",
    #     "index": "<index_name>",
    #     "interval": "<interval_value>",
    #     "python.version": "python3",
    #   },
    # }
    session_key = inputs.metadata["session_key"]

    # Initialize KV Store checkpointer
    try:
        ckpt = checkpointer.KVStoreCheckpointer(
            collection_name=f"{ADDON_NAME}_checkpoints",
            session_key=session_key,
            app=ADDON_NAME,
        )
    except Exception as e:
        # Fallback to a generic logger if input-specific logger isn't available yet
        logging.error(f"Failed to initialize KVStore checkpointer: {e}")
        return

    for input_name, input_item in inputs.inputs.items():
        normalized_input_name = input_name.split("/")[-1]
        logger = logger_for_input(normalized_input_name)

        try:
            log_level = conf_manager.get_log_level(
                logger=logger,
                session_key=session_key,
                app_name=ADDON_NAME,
                conf_name="qualtrics_audit_settings",
            )
            logger.setLevel(log_level)
            log.modular_input_start(logger, normalized_input_name)

            account_name = input_item.get("account")
            account_config = get_account_config(session_key, account_name)
            api_key = account_config["api_key"]
            domain = account_config["domain"]

            # Get checkpoint key and determine date range for this run
            checkpoint_key = get_checkpoint_key(normalized_input_name, account_name)
            start_date = get_last_end_date(ckpt, checkpoint_key)
            end_date = datetime.utcnow()  # Always use current time as end date

            logger.info(f"Processing data from {start_date} to {end_date}")

            # Fetch data with date range
            data = get_data_from_api(logger, api_key, domain, start_date, end_date)

            # Write events to Splunk
            events_written = 0
            for line in data:
                event_writer.write_event(
                    smi.Event(
                        data=json.dumps(line, ensure_ascii=False, default=str),
                        index=input_item.get("index"),
                    )
                )
                events_written += 1

            # Save checkpoint with this run's end date (which becomes next run's start date)
            save_checkpoint(ckpt, checkpoint_key, end_date)
            logger.info(f"Updated checkpoint with end date: {end_date}")

            log.events_ingested(
                logger,
                input_name,
                events_written,
                input_item.get("index"),
                account=account_name,
            )
            log.modular_input_end(logger, normalized_input_name)

        except Exception as e:
            log.log_exception(
                logger,
                e,
                "checkpoint_error",
                msg_before=f"Exception raised while ingesting data for {normalized_input_name}: ",
            )
