
import pandas as pd
from pathlib import Path


def perform_eda():

    input_file = Path("data/processed/cleaned_urls.csv")

    if not input_file.exists():
        print("ERROR: Cleaned dataset not found.")
        return

    df = pd.read_csv(input_file)

    if df.empty:
        print("Dataset is empty.")
        return

    print("\n========== DATASET OVERVIEW ==========")

    print("Total records:", len(df))
    print("Total columns:", len(df.columns))

    print("\nColumn names:")
    print(df.columns.tolist())

    print("\n========== MISSING VALUES ==========")

    print(df.isnull().sum())

    print("\n========== DUPLICATE RECORDS ==========")

    print("Duplicate URLs:", df["url"].duplicated().sum())

    print("\n========== URL STATUS ANALYSIS ==========")

    if "url_status" in df.columns:
        print(df["url_status"].value_counts(dropna=False))
    else:
        print("URL status column not available.")

    print("\n========== THREAT ANALYSIS ==========")

    if "threat" in df.columns:
        print(df["threat"].value_counts(dropna=False))
    else:
        print("Threat column not available.")

    print("\n========== TOP HOSTS ==========")

    if "host" in df.columns:
        print(df["host"].value_counts().head(10))
    else:
        print("Host column not available.")

    print("\n========== DATA SUMMARY ==========")

    print(df.describe(include="all").to_string())

    print("\nEDA completed successfully!")


if __name__ == "__main__":
    perform_eda()
