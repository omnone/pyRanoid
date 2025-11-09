"""
PyRanoid CLI module.

This module provides a command-line interface for the PyRanoid steganography
application. It allows users to encrypt files into images and decrypt files
from images using an interactive terminal interface.
"""

import argparse
import sys
import getpass
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from .utils import (
    encrypt_image,
    decrypt_image,
    generate_rsa_keypair,
    save_private_key,
    save_public_key,
    is_private_key_encrypted,
)
import os
import textwrap


console = Console()

# --------------------------------------------------------------------------------------------


def print_banner():
    """Print the application banner."""

    banner = textwrap.dedent(r"""
                     ____                   _     _                                                                                       
         _ __  _   _|  _ \ __ _ _ __   ___ (_) __| |                                                                                      
        | '_ \| | | | |_) / _` | '_ \ / _ \| |/ _` |                                                                                     
        | |_) | |_| |  _ < (_| | | | | (_) | | (_| |                                                                                     
        | .__/ \__, |_| \_\__,_|_| |_|\___/|_|\__,_|                                                                                     
        |_|    |___/    
    """)

    console.print(
        Panel(
            Text(banner + "\n(github.com/omnone/pyRanoid)", style="purple"),
            border_style="purple",
        )
    )


# --------------------------------------------------------------------------------------------


def validate_path(path_str, must_exist=True):
    """Validate that a path exists."""
    path = Path(path_str)
    if must_exist and not path.exists():
        console.print(f"[red]Error: Path '{path_str}' does not exist.[/red]")
        sys.exit(1)
    return path_str


# --------------------------------------------------------------------------------------------


def get_password(verify=False):
    """Get password from user with optional verification."""
    password = getpass.getpass("Enter password: ")
    if verify:
        password_verify = getpass.getpass("Reenter password: ")
        if password != password_verify:
            console.print("[red]Error: Passwords don't match.[/red]")
            sys.exit(1)
    return password


# --------------------------------------------------------------------------------------------


def get_key_password():
    """Get password for RSA private key (required for encrypted keys)."""
    password = getpass.getpass("Enter RSA private key password: ")
    return password if password else None


# --------------------------------------------------------------------------------------------


def encrypt_command(args):
    """Handle the encrypt command."""
    validate_path(args.image, must_exist=True)
    validate_path(args.target, must_exist=True)

    if args.public_key and args.password:
        console.print(
            "[red]Error: Cannot use both --public-key and --password. Choose one mode.[/red]"
        )
        sys.exit(1)
    elif not args.public_key and not args.password:
        console.print(
            "[red]Error: Must provide either --public-key (RSA mode) or --password (password mode).[/red]"
        )
        sys.exit(1)

    try:
        with console.status(
            f"[bold green]Hiding {args.target} in {args.image}...[/bold green]",
            spinner="dots",
        ):
            if args.public_key:
                validate_path(args.public_key, must_exist=True)
                encrypt_image(
                    args.image,
                    args.target,
                    output_path=args.output,
                    rsa_public_key_path=args.public_key,
                )
                absolute_output_path = os.path.abspath(args.output)
                console.print(
                    f"[green]✓ Successfully hidden {args.target} in {args.image} as {absolute_output_path}[/green]"
                )
                console.print(
                    "[yellow]Note: A random password was generated and encrypted with your RSA public key.[/yellow]"
                )
            else:
                password = (
                    args.password
                    if args.password is not True
                    else get_password(verify=True)
                )
                encrypt_image(
                    args.image,
                    args.target,
                    output_path=args.output,
                    password=password,
                )
                absolute_output_path = os.path.abspath(args.output)
                console.print(
                    f"[green]✓ Successfully hidden {args.target} in {args.image} as {absolute_output_path}[/green]"
                )
    except Exception as e:
        console.print(f"[red]Error during encryption: {e}[/red]")
        sys.exit(1)


# --------------------------------------------------------------------------------------------


def decrypt_command(args):
    """Handle the decrypt command."""
    validate_path(args.image, must_exist=True)

    output_dir = Path(args.output_dir)
    if not output_dir.exists():
        console.print(
            f"[yellow]Warning: Output directory '{args.output_dir}' does not exist. Creating it...[/yellow]"
        )
        output_dir.mkdir(parents=True, exist_ok=True)

    if args.private_key and args.password:
        console.print(
            "[red]Error: Cannot use both --private-key and --password. Choose one mode.[/red]"
        )
        sys.exit(1)
    elif not args.private_key and not args.password:
        console.print(
            "[red]Error: Must provide either --private-key (RSA mode) or --password (password mode).[/red]"
        )
        sys.exit(1)

    try:
        if args.private_key:
            validate_path(args.private_key, must_exist=True)

            if args.key_password:
                key_password = args.key_password
            elif is_private_key_encrypted(args.private_key):
                key_password = get_key_password()
                if not key_password:
                    console.print(
                        "[red]Error: The private key is encrypted but no password was provided.[/red]"
                    )
                    sys.exit(1)
            else:
                key_password = None

            max_attempts = 3
            for attempt in range(max_attempts):
                try:
                    with console.status(
                        f"[bold green]Decrypting {args.image}...[/bold green]",
                        spinner="dots",
                    ):
                        files = decrypt_image(
                            args.image,
                            output_dir=args.output_dir,
                            rsa_private_key_path=args.private_key,
                            key_password=key_password,
                        )
                    break
                except ValueError as e:
                    error_msg = str(e)
                    if "Incorrect password" in error_msg:
                        if attempt < max_attempts - 1:
                            console.print(
                                f"[red]Incorrect password. Attempt {attempt + 2}/{max_attempts}[/red]"
                            )
                            key_password = get_key_password()
                            if not key_password:
                                console.print(
                                    "[red]Error: Password cannot be empty.[/red]"
                                )
                                sys.exit(1)
                        else:
                            console.print(
                                f"[red]Error: Maximum attempts reached. {e}[/red]"
                            )
                            sys.exit(1)
                    else:
                        raise
        else:
            password = (
                args.password
                if args.password is not True
                else get_password(verify=False)
            )
            with console.status(
                f"[bold green]Decrypting {args.image}...[/bold green]", spinner="dots"
            ):
                files = decrypt_image(
                    args.image,
                    output_dir=args.output_dir,
                    password=password,
                )

        absolute_output_dir = os.path.abspath(args.output_dir)
        console.print(
            f"[green]✓ Successfully extracted file(s) {', '.join(files)} to {absolute_output_dir}[/green]"
        )
    except Exception as e:
        console.print(f"[red]Error during decryption: {e}[/red]")
        sys.exit(1)


# --------------------------------------------------------------------------------------------


def keygen_command(args):
    """Handle the keygen command to generate RSA key pairs."""
    try:
        if Path(args.private_key).exists() or Path(args.public_key).exists():
            console.print("[yellow]Warning: Key files already exist.[/yellow]")
            response = input("Overwrite existing keys? (yes/no): ")
            if response.lower() not in ["yes", "y"]:
                console.print("[yellow]Key generation cancelled.[/yellow]")
                return

        console.print(
            "[cyan]Do you want to encrypt the private key with a password?[/cyan]"
        )
        console.print("[cyan](Highly recommended for security)[/cyan]")
        encrypt_key = input("Encrypt private key? (yes/no): ")

        key_password = None
        if encrypt_key.lower() in ["yes", "y"]:
            key_password = getpass.getpass("Enter password for private key: ")
            key_password_verify = getpass.getpass("Reenter password: ")
            if key_password != key_password_verify:
                console.print("[red]Error: Passwords don't match.[/red]")
                sys.exit(1)

        with console.status(
            "[bold green]Generating RSA key pair (4096-bit)...[/bold green]",
            spinner="dots",
        ):
            private_key, public_key = generate_rsa_keypair()
            save_private_key(private_key, args.private_key, key_password)
            save_public_key(public_key, args.public_key)

        console.print("[green]✓ RSA key pair generated successfully![/green]")
        console.print(
            f"[green]  Private key: {os.path.abspath(args.private_key)}[/green]"
        )
        console.print(
            f"[green]  Public key: {os.path.abspath(args.public_key)}[/green]"
        )
        console.print(
            "[yellow]⚠ Keep your private key secure! Anyone with access to it can decrypt your files.[/yellow]"
        )
    except Exception as e:
        console.print(f"[red]Error during key generation: {e}[/red]")
        sys.exit(1)


# --------------------------------------------------------------------------------------------


def main():
    """Main CLI entry point."""
    print_banner()

    parser = argparse.ArgumentParser(
        description="PyRanoid - Steganography tool for encrypting files into images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    encrypt_parser = subparsers.add_parser(
        "encrypt", help="Encrypt a file into an image"
    )
    encrypt_parser.add_argument("image", help="Path to the carrier image")
    encrypt_parser.add_argument("target", help="Path to the file to encrypt")
    encrypt_parser.add_argument(
        "-o",
        "--output",
        default="output.png",
        help="Output image path (default: output.png)",
    )

    encrypt_mode = encrypt_parser.add_mutually_exclusive_group(required=True)
    encrypt_mode.add_argument(
        "--public-key",
        dest="public_key",
        help="Path to RSA public key file (RSA mode)",
    )
    encrypt_mode.add_argument(
        "-p",
        "--password",
        nargs="?",
        const=True,
        default=None,
        help="Use password mode (will prompt if no password provided)",
    )

    decrypt_parser = subparsers.add_parser(
        "decrypt", help="Decrypt a file from an image"
    )
    decrypt_parser.add_argument(
        "image", help="Path to the image containing encrypted data"
    )
    decrypt_parser.add_argument(
        "-d",
        "--output-dir",
        default=".",
        help="Output directory for extracted files (default: current directory)",
    )

    decrypt_mode = decrypt_parser.add_mutually_exclusive_group(required=True)
    decrypt_mode.add_argument(
        "--private-key",
        dest="private_key",
        help="Path to RSA private key file (RSA mode)",
    )
    decrypt_mode.add_argument(
        "-p",
        "--password",
        nargs="?",
        const=True,
        default=None,
        help="Use password mode (will prompt if no password provided)",
    )

    decrypt_parser.add_argument(
        "-k",
        "--key-password",
        default=None,
        help="Password for RSA private key (if encrypted)",
    )

    keygen_parser = subparsers.add_parser(
        "keygen", help="Generate RSA key pair for encryption/decryption"
    )
    keygen_parser.add_argument(
        "-priv",
        "--private-key",
        default="private_key.pem",
        help="Output path for private key (default: private_key.pem)",
    )
    keygen_parser.add_argument(
        "-pub",
        "--public-key",
        default="public_key.pem",
        help="Output path for public key (default: public_key.pem)",
    )

    args = parser.parse_args()

    if args.command == "encrypt":
        encrypt_command(args)
    elif args.command == "decrypt":
        decrypt_command(args)
    elif args.command == "keygen":
        keygen_command(args)
    else:
        parser.print_help()
        sys.exit(0)


# --------------------------------------------------------------------------------------------

if __name__ == "__main__":
    main()
