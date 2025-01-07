package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// Initialize the database connection and create the users and messages tables if they don't exist
func initDB() {
	var err error
	// Open the SQLite database (if the file doesn't exist, it will be created)
	db, err = sql.Open("sqlite3", "./go_login_system.db")
	if err != nil {
		log.Fatal(err)
	}

	// Check if the connection is established
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to the SQLite database!")

	// Create users table
	createUsersTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL
	);`
	_, err = db.Exec(createUsersTableQuery)
	if err != nil {
		log.Fatal("Error creating users table: ", err)
	}

	// Create groups table
	createGroupsTableQuery := `
	CREATE TABLE IF NOT EXISTS groups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	_, err = db.Exec(createGroupsTableQuery)
	if err != nil {
		log.Fatal("Error creating groups table: ", err)
	}

	// Create group_members table
	createGroupMembersTableQuery := `
	CREATE TABLE IF NOT EXISTS group_members (
		group_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (group_id, user_id),
		FOREIGN KEY (group_id) REFERENCES groups(id),
		FOREIGN KEY (user_id) REFERENCES users(id)
	);`
	_, err = db.Exec(createGroupMembersTableQuery)
	if err != nil {
		log.Fatal("Error creating group_members table: ", err)
	}

	// Create messages table with group_id
	createMessagesTableQuery := `
	CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sender_id INTEGER NOT NULL,
		group_id INTEGER NOT NULL,
		content TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (sender_id) REFERENCES users(id),
		FOREIGN KEY (group_id) REFERENCES groups(id)
	);`
	_, err = db.Exec(createMessagesTableQuery)
	if err != nil {
		log.Fatal("Error creating messages table: ", err)
	}

	fmt.Println("Database tables are ready!")
}

// Function to validate user against the SQLite database
func validateUser(username, password string) bool {
	var storedHash string

	// Query the database for the user
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&storedHash)
	if err != nil {
		if err == sql.ErrNoRows {
			// User not found
			return false
		}
		log.Println("Error querying the database:", err)
		return false
	}

	// Compare the entered password with the stored hash
	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	if err != nil {
		// Passwords don't match
		return false
	}

	// Credentials are valid
	return true
}

// Function to register a new user
func registerUser(username, password string) error {
	// Check if the username already exists
	var existingUsername string
	err := db.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&existingUsername)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if existingUsername != "" {
		return fmt.Errorf("username already taken")
	}

	// Hash the password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Insert the user into the database
	_, err = db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, string(passwordHash))
	if err != nil {
		return err
	}

	return nil
}

// Helper function to get user ID from username
func getUserID(username string) (int, error) {
	var id int
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&id)
	return id, err
}

// Helper function to get or create a chat group with multiple users
func getOrCreateChatGroup(groupName string, users ...string) (int, error) {
	if len(users) < 2 {
		return 0, fmt.Errorf("chat group must have at least 2 users")
	}

	// Get all user IDs
	userIDs := make([]int, len(users))
	for i, username := range users {
		id, err := getUserID(username)
		if err != nil {
			return 0, fmt.Errorf("error getting user ID for %s: %v", username, err)
		}
		userIDs[i] = id
	}

	// Check if a group already exists with exactly these users
	query := `
		WITH GroupCounts AS (
			SELECT gm.group_id, COUNT(*) as member_count
			FROM group_members gm
			GROUP BY gm.group_id
			HAVING member_count = ?
		)
		SELECT gm.group_id
		FROM group_members gm
		JOIN GroupCounts gc ON gm.group_id = gc.group_id
		WHERE gm.user_id IN (?` + strings.Repeat(",?", len(userIDs)-1) + `)
		GROUP BY gm.group_id
		HAVING COUNT(*) = ?`

	queryArgs := make([]interface{}, 0, len(userIDs)+2)
	queryArgs = append(queryArgs, len(userIDs)) // member_count
	for _, id := range userIDs {
		queryArgs = append(queryArgs, id)
	}
	queryArgs = append(queryArgs, len(userIDs)) // HAVING COUNT

	var groupID int
	err := db.QueryRow(query, queryArgs...).Scan(&groupID)
	if err == nil {
		return groupID, nil
	}
	if err != sql.ErrNoRows {
		return 0, err
	}

	// Create new group
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Create the group with provided name or generate default name
	if groupName == "" {
		groupName = fmt.Sprintf("Chat_%s", strings.Join(users, "_"))
	}

	result, err := tx.Exec(`
		INSERT INTO groups (name) 
		VALUES (?)`,
		groupName)
	if err != nil {
		return 0, err
	}

	groupID64, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	groupID = int(groupID64)
	fmt.Println("Group created with ID:", groupID, "and name:", groupName, "with ID:", groupID64)

	// Add all users to the group
	valueStrings := make([]string, len(userIDs))
	valueArgs := make([]interface{}, 0, len(userIDs)*2)

	for i, userID := range userIDs {
		valueStrings[i] = "(?, ?)"
		valueArgs = append(valueArgs, groupID, userID)
	}

	query = fmt.Sprintf(`
		INSERT INTO group_members (group_id, user_id) 
		VALUES %s`, strings.Join(valueStrings, ","))

	fmt.Println("query:", query, "valueArgs:", valueArgs)

	_, err = tx.Exec(query, valueArgs...)
	if err != nil {
		return 0, err
	}

	err = tx.Commit()
	if err != nil {
		return 0, err
	}

	return groupID, nil
}
