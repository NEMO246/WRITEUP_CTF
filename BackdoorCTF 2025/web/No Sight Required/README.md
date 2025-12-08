## BackdoorCTF 2025 - No Sight Required Write-up

![Challenge Interface](images/Title.png)

### Step 1: Initial Analysis and Reconnaissance

The challenge presents a minimal "User Directory" service. The description emphasizes that "less is secure" and the application only provides "clean yes/no answers." This behavior is a strong indicator of a **Blind SQL Injection** vulnerability.

The application takes a user ID as input (e.g., `?id=1`) and returns "User found!" if the ID exists, or nothing/error if it doesn't. Since we don't see the database output directly, we cannot use UNION-based injection. Instead, we must infer data by asking the database True/False questions.

### Step 2: Automated Vulnerability Detection

Given the blind nature of the injection, manual exploitation can be time-consuming. We used **sqlmap** to automate the detection process.

We ran the initial scan against the target URL:

```bash
sqlmap -u "http://104.198.24.52:6013/search?id=1" --batch
```

**Sqlmap** successfully identified two types of injection:
1.  **Boolean-based blind:** The server response changes based on whether the query is TRUE or FALSE.
2.  **Time-based blind:** The server delays the response when a specific time-heavy command is executed.

It also identified the backend DBMS as **SQLite**.

![Sqlmap Injection Detection](images/1.png)

### Step 3: Database Enumeration

Once the vulnerability was confirmed, we proceeded to enumerate the database tables to find where the flag might be hidden.

```bash
sqlmap -u "http://104.198.24.52:6013/search?id=1" --tables --batch
```

The tool identified two tables in the database:
*   `users` (likely containing the standard directory data)
*   `secret_flags` (the obvious target)

![Sqlmap Tables Enumeration](images/2.png)

### Step 4: Data Exfiltration

With the target table identified as `secret_flags`, we instructed `sqlmap` to dump its content. We increased the number of threads to speed up the blind extraction process.

```bash
sqlmap -u "http://104.198.24.52:6013/search?id=1" -T secret_flags --dump --batch --threads=5
```

![Sqlmap Dump Flag](images/3.png)

Sqlmap extracted the data character by character and successfully retrieved the flag from the `flag` column.

![Sqlmap Dump Flag](images/4.png)

### Flag

`flag{bl1nd_but_n0t_l0st_1n_th3_d4rk}`
