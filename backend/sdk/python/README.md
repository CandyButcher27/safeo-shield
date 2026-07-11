# SafeO Python SDK

```bash
pip install requests
```

```python
from safeo_sdk.python.client import SafeOClient

client = SafeOClient(api_key="your-key")
result = client.scan(
    "1 OR 1=1; DROP TABLE users;--",
    context={"user_id": "u123", "source_system": "myapp"},
)
print(result["decision"])  # BLOCK
```
