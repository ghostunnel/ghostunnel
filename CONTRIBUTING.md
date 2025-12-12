# Contributing guidelines

If you would like to contribute code to ghostunnel you can do so through GitHub
by forking the repository and sending a pull request.

When submitting code, please make efforts to follow existing conventions and
style in order to keep the code as readable as possible. Please also make sure
all tests pass by running `mage test`, and format your code with `go fmt`.

Note that ghostunnel relies heavily on integration tests written in Python that
run checks on a live instance. If you are adding new features or changing
existing behavior, please add/update the integration tests in the tests
directory accordingly.
