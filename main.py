
from baseline import create_baseline, load_baseline, update_baseline


def display_baseline():
    baseline = load_baseline()

    if not baseline:
        print("No baseline available.")
        return

    print("\nSaved baseline:")
    for path, file_hash in baseline.items():
        print(path, ":", file_hash)


def main():
    while True:
        print("\n========== HASH GUARD ==========")
        print("1. Create baseline")
        print("2. View baseline")
        print("3. Update baseline")
        print("4. Exit")

        choice = input("\nEnter your choice: ")

        if choice == "1":
            folder = input("Enter folder path: ")
            create_baseline(folder)

        elif choice == "2":
            display_baseline()

        elif choice == "3":
            folder = input("Enter folder path: ")
            update_baseline(folder)

        elif choice == "4":
            print("Exiting Hash Guard.")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
