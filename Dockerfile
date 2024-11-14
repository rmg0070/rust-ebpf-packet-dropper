# # Use Ubuntu 22.04 as the base image
# FROM ubuntu:22.04

# # Set environment variables to prevent prompts during installation
# ENV DEBIAN_FRONTEND=noninteractive

# # Set the working directory
# WORKDIR /workspace

# # Copy the local files into the container
# COPY . .

# # Install dependencies including net-tools and sudo
# RUN apt-get update && apt-get install -y \
#     sudo \
#     curl \
#     build-essential \
#     libssl-dev \
#     pkg-config \
#     clang \
#     llvm \
#     git \
#     net-tools \
#     nginx \
#     && rm -rf /var/lib/apt/lists/*

# # Install the latest version of Rust
# RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain stable -y

# # Add the Rust binaries to the PATH
# ENV PATH="/root/.cargo/bin:${PATH}"

# # Install additional toolchains and components
# RUN rustup install stable \
#     && rustup toolchain install nightly --component rust-src \
#     && cargo install bpf-linker

# # Allow all users to run commands without a password
# RUN echo 'ALL            ALL = (ALL) NOPASSWD: ALL' >> /etc/sudoers

# # Build the Rust project and eBPF components
# RUN sudo cargo task build-ebpf
# RUN sudo cargo build

# EXPOSE 80

# # The container will run an interactive shell by default
# CMD ["/bin/bash"]
# Use Ubuntu 22.04 as the base image
# FROM ubuntu:22.04

# # Set environment variables to prevent prompts during installation
# ENV DEBIAN_FRONTEND=noninteractive \
#     PATH="/root/.cargo/bin:${PATH}"

# # Set the working directory
# WORKDIR /workspace

# # Copy the local files into the container
# COPY . .

# # Install necessary packages
# RUN apt-get update && apt-get install -y \
#     sudo \
#     curl \
#     build-essential \
#     libssl-dev \
#     pkg-config \
#     clang \
#     llvm \
#     git \
#     net-tools \
#     nginx \
#     && apt-get clean \
#     && rm -rf /var/lib/apt/lists/* \
#     # Install the latest version of Rust using the Rust installer script
#     && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain stable -y \
#     # Install additional toolchains and components
#     && rustup install stable \
#     && rustup toolchain install nightly --component rust-src \
#     && cargo install bpf-linker \
#     # Configure sudoers to allow all users to run commands without a password
#     && echo 'ALL            ALL = (ALL) NOPASSWD: ALL' >> /etc/sudoers

# # Build the Rust project and eBPF components
# # RUN sudo cargo task build-ebpf
# # RUN sudo cargo build

# # Expose port 80 for the service to be accessible
# EXPOSE 80

# # Define the default command to run when starting the container
# CMD ["/bin/bash"]


# Use Ubuntu 22.04 as the base image
FROM ubuntu:22.04

# Set environment variables to prevent prompts during installation
ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/root/.cargo/bin:${PATH}"

# Set the working directory
WORKDIR /workspace

# Copy the local files into the container
COPY . .

# Install necessary packages
RUN apt-get update && apt-get install -y \
    sudo \
    curl \
    build-essential \
    libssl-dev \
    pkg-config \
    clang \
    llvm \
    git \
    net-tools \
    nginx \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    # Install the latest version of Rust using the Rust installer script
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain stable -y \
    # Install additional toolchains and components
    && rustup install stable \
    && rustup toolchain install nightly --component rust-src \
    && cargo install bpf-linker \
    # Configure sudoers to allow all users to run commands without a password
    && echo 'ALL            ALL = (ALL) NOPASSWD: ALL' >> /etc/sudoers \
    # Build the Rust project and eBPF components
    && cargo task build-ebpf \
    && cargo build

# Expose port 80 for the service to be accessible
EXPOSE 80

# Define the default command to run when starting the container
CMD ["/bin/bash"]
