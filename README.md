# CounterSync

An assessment utility for AWS AppSync GraphQL.

## Quick Start:
Install the tool

```sh
git clone git@github.com:c6fc/countersync.git
cd countersync
npm install -g
```

Check for an AppSync GraphQL endpoint and credentials on a given page source.

```sh
countersync https://my.site/path-with-graphql-in-source
```

CounterSync will scan the page source for a GraphQL endpoint, API key, long-term IAM credentials, or Cognito identity pool. It will inspect the endpoint, retrieve the schema, map the fields, and expose easy querying capabilities.

Cached schemas are stored in `~/.countersync`.