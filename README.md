# apt-actions

Run custom actions before and after apt package transactions.

apt-actions provides a simple rule-based mechanism for executing commands when packages are installed, upgraded, downgraded, reinstalled or removed.

Actions can match package names using shell-style globs and can access information about the matched package through environment variables.

## Warning

apt-actions is currently experimental and should not be considered production-ready. It is provided without any guarantee of correctness, reliability or suitability
for a particular purpose. 

## Inspiration

The project was inspired by dnf transaction plugins.
apt-actions is an independent implementation for the apt/dpkg ecosystem. **It is not a port of dnf** and does not contain any dnf source code.

## License

Licensed under the GNU General Public License v2.0 or later.