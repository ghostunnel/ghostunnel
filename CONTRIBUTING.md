# Contributing

If you would like to contribute code to ghostunnel you can do so through GitHub
by forking the repository and sending a pull request.

When submitting code, please make every effort to follow existing conventions
and style in order to keep the code as readable as possible. Please also make
sure all tests pass by running `make test`, and format your code with `go fmt`.

Note that ghostunnel relies heavily on integration tests written in Python that
run checks on a live instance. If you are adding new features or changing 
existing behavior, please add/update the integration tests in the tests directory
accordingly.

Before your code can be accepted into the project you must also sign the
[Individual Contributor License Agreement][1].

 [1]: https://spreadsheets.google.com/spreadsheet/viewform?formkey=dDViT2xzUHAwRkI3X3k5Z0lQM091OGc6MQ&ndplr=1
