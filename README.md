# Multicast Analyzer Tool DataMiner Protocol

## Overview
The Multicast Analyzer Tool DataMiner Protocol is a C# application designed to facilitate the detection of conflicting multicast IP addresses within a network. It provides a user-friendly interface for configuring network interfaces, defining multicast IP addresses and ports to search for, setting timeout parameters for inactive packet detection, and specifying the duration of tests.

## Key Features
- **Conflict Multicast IP Address Detection**: Detect instances where multiple source IP addresses are generating the same multicast group within the network.
- **Network Interface Selection**: Specify network interfaces for testing.
- **Multicast IP and Port Configuration**: Define multicast IP addresses and ports to search for.
- **Timeout Configuration**: Set timeout values to confirm inactive packet sources.
- **Test Duration Setting**: Specify the duration of tests.
- **Results Display**: View analysis results, including source IP addresses and ports, in a clear and organized manner.

## Installation
1. Clone this repository to your local machine.
2. Open the solution in Visual Studio or your preferred C# IDE.
3. Build the solution to generate the executable.

## Usage
1. Run the generated executable.
2. Configure network interfaces and settings in the Settings page.
3. Start the analysis to detect conflicting multicast IP addresses.
4. View analysis results in the Multicast Analyzer Table on the Main General page.

## Dependencies
- [C#](https://docs.microsoft.com/en-us/dotnet/csharp/)
- [.NET Framework](https://dotnet.microsoft.com/download)

## Contributing
Contributions are welcome! If you have any suggestions, bug reports, or feature requests, please open an issue or submit a pull request.

## License
This project is licensed under the [MIT License](LICENSE).
