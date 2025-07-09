import os
# Add these imports at the top
from elabapi_python import ApiClient, ExperimentsApi, ItemsApi
from dotenv import load_dotenv

load_dotenv()

class ELNClient:
    def __init__(self):
        self.config = ApiClient(
            host=os.getenv("ELABFTW_URL", "https://your-elab-instance.com")
        )
        self.config.api_key = {'Authorization': os.getenv("ELABFTW_API_KEY")}
        self.experiments_api = ExperimentsApi(self.config)
        self.items_api = ItemsApi(self.config)
    
    def get_experiments(self, limit: int = 10, offset: int = 0):
        """Get paginated list of experiments"""
        return self.experiments_api.get_experiments(limit=limit, offset=offset)
    
    def get_experiment_by_id(self, exp_id: int):
        """Get single experiment with full details"""
        return self.experiments_api.get_experiment(exp_id)
    
    def search_experiments(self, query: str):
        """Search experiments by title/tags"""
        return self.experiments_api.get_experiments(q=query)
    
    def create_experiment(self, title: str, body: str, tags: list = []):
        """Create new experiment in ELN"""
        return self.experiments_api.post_experiment(
            title=title,
            body=body,
            tags=tags
        )

def get_eln_client():
    """Dependency injection for FastAPI routes"""
    return ELNClient()