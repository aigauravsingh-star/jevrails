from openai import OpenAI

from jevrails import Guard, GuardedOpenAI, Policy
from jevrails.backends import JevBackend


client = GuardedOpenAI(
    OpenAI(),
    Guard(policy=Policy.default(), backend=JevBackend.from_env()),
)

response = client.chat.completions.create(
    model="gpt-5-mini",
    messages=[{"role": "user", "content": "Hello"}],
)
print(response)
