# Vault RedShift Plugin

This plugin allows you to use Vault to manage One-Time Users for the AWS RedShift database.

# Building

You'll need an up-to-date Go distribution set up.   Clone this repository into the appropriate place (or
`go get github.com/ironsource/vault-redshift-plugin`)  Then `go get github.com/hashicorp/vault` and
`go get github.com/lib/pq`.

These are not bundled as dependencies to allow for upstream API version changes in Vault.  The plugin system
demands that the plugin API version matches that of your local vault.  If you want to build this plugin for
an older version of Vault, you should go to the checkout of vault in your $GOPATH and checkout the tag matching
the target version of Vault.

To build, simply run `go build`

# Configuring Vault

Once you have the plugin binary, check (or verify) the SHA256 hash of the file.  On GNU systems, this
can be done by running `sha256sum vault-redshift-plugin`

Copy the vault-redshift-plugin to your vault server's filesystem.  If this is your first plugin, you'll need to
create a protected directory to hold all Vault plugins, and you will need to configure the path to this
directory in the root section of the Vault configuration file `plugin_directory = "/path/to/plugins"`.  Make sure
that the plugin is marked as an executable, and if you have an mlock-aware platform ensure that the user running
vault has the proper capabilities (`sudo setcap cap_ipc_lock=+ep $(readlink -f /path/to/plugins/vault-redshift-plugin)`)

To add the plugin to the Vault registry, run the following command (remember to replace the value of sha_256 with the
hash you calculated/verified above):

`vault write sys/plugins/catalog/redshift-database-plugin command="vault-redshift-plugin" sha_256=b890f59b8f90b73ea5e7f4b3fa00bbbcdfe3c34eb13da89e064b14b8edb8f96f`

# Configuring the plugin

The plugin works similar to the other database plugins included in Vault.  Follow the instructions at https://www.vaultproject.io/docs/secrets/databases/postgresql.html
except that when creating a database config, use the value `redshift-database-plugin` instead of `postgresql-database-plugin`

# Troubleshooting

- I get the error "[ERR] plugin: plugin tls init: no address for the vault found" when trying to load the plugin

Try setting the redirect_addr configuration setting - see https://www.vaultproject.io/docs/concepts/ha.html#client-redirection.  In a dev
scenario this is often as simple as setting the environment variable `VAULT_REDIRECT_ADDR` to http://127.0.0.1:8200

- I get the error "panic: sql: Register called twice for driver postgres"

This can happen in some build environments, and is called by Go initializing both the pq we depend on at compile time and the pq that
vault uses internally.  To get around this, rename the directory `$GOPATH/github.com/hashicorp/vault/vendor/github.com/lib/pq` to any other name
and then `go build` the plugin again.

- I tried to change the plugin, but after rebuilding and updating the sha256 in Vault, it still seems to be running the old version

Vault caches its plugins.  To force a reload of a database plugin without restarting Vault, use the `reset` action - for example
`vault write -f databases/reset/redshift` (see https://www.vaultproject.io/api/secret/databases/index.html#reset-connection)

# Author
Copyright (c) 2017, ironSource Ltd.

For licensing information, see LICENSE