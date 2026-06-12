from security_dashboard.analysis import AnalysisBackgroundState
from security_dashboard.components import get_asset_table_configs

analysis_background_state = AnalysisBackgroundState()
ASSET_TABLE_CONFIGS = get_asset_table_configs()
TABLE_ID_MAP = {config["id"]: config for config in ASSET_TABLE_CONFIGS}
