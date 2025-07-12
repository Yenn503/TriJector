/*
--------------------------------------------------------------------------------------------
@Author: Yenn
@website: 
--------------------------------------------------------------------------------------------
*/

#include "common.h"
#include "Inject.h"
#include "NTinject.h"
#include "Win32Inject.h"

void DisplayMenu() {
    printf("\nChoose injection method:\n");
    printf("1. Direct Syscalls\n");
    printf("2. NTAPI (Native)\n");
    printf("3. Win32\n");
    printf("4. Exit\n");
    printf("\nEnter choice (1-4): ");
}

int main() {
    int choice;
    BOOL success = FALSE;

    // Display the banner
    PrintBanner();

    while (1) {
        DisplayMenu();
        if (scanf_s("%d", &choice) != 1) {
            while (getchar() != '\n'); // Clear input buffer
            continue;
        }
        getchar(); // Consume newline

        switch (choice) {
            case 1:
                INFO("Starting Direct Syscalls injection...");
                success = FetchResource();
                break;

            case 2:
                INFO("Starting NTAPI injection...");
                success = FetchResourceNTAPI();
                break;

            case 3:
                INFO("Starting Win32 injection...");
                success = FetchResourceWin32();
                break;

            case 4:
                INFO("Exiting...");
                return 0;

            default:
                WARN("Invalid choice. Please select 1-4");
                continue;
        }

        if (success) {
            INFO("Injection completed successfully");
        } else {
            PRINT_ERROR("Injection failed", GetLastError());
        }

        printf("\nPress Enter to continue...");
        getchar();
        system("cls"); // Clear screen
        PrintBanner(); // Show banner again
    }

    return 0;
}