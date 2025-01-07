package main

import (
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"log"
	"net/http"
	"slices"

	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"github.com/microcosm-cc/bluemonday"
)

var store = sessions.NewCookieStore([]byte("secret-key-replace-this-in-production"))
var sanitizer = bluemonday.UGCPolicy()

func init() {
	// Allow specific HTML elements and attributes for rich text
	sanitizer.AllowElements("p", "br", "strong", "em", "u", "s", "blockquote", "pre", "ul", "ol", "li")
	sanitizer.AllowLists()

	// Allow specific styling attributes
	sanitizer.AllowStyles("color", "background-color").OnElements("span")
	sanitizer.AllowElements("span")

	// Allow class attributes for code blocks
	sanitizer.AllowAttrs("class").OnElements("pre")
	sanitizer.AllowAttrs("spellcheck").OnElements("div")
}

// Debug structures for JSON output
type DebugUser struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type DebugGroup struct {
	ID        int            `json:"id"`
	Name      string         `json:"name"`
	CreatedAt string         `json:"created_at"`
	Members   []string       `json:"members"`
	Messages  []DebugMessage `json:"messages"`
}

type DebugMessage struct {
	ID        int    `json:"id"`
	Sender    string `json:"sender"`
	GroupID   int    `json:"group_id"`
	Content   string `json:"content"`
	Timestamp string `json:"timestamp"`
}

// Serve the HTML login page
func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Serve the HTML login page
		http.ServeFile(w, r, "../static/login.html")
	} else if r.Method == http.MethodPost {
		// Handle login form submission
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Validate user credentials
		if validateUser(username, password) {
			// Create a new session for the user
			session, _ := store.Get(r, "session-name")
			session.Values["authenticated"] = true
			session.Values["username"] = username
			session.Save(r, w)

			fmt.Println("Login successful for user:", username)

			// Redirect to groupchat page after successful login
			http.Redirect(w, r, "/groupchat", http.StatusSeeOther)
		} else {
			http.Error(w, "Invalid login credentials", http.StatusUnauthorized)
		}
	}
}

// Serve the registration page
func registerPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Serve the HTML registration page
		http.ServeFile(w, r, "../static/register.html")
	} else if r.Method == http.MethodPost {
		// Handle registration form submission
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Register new user
		if err := registerUser(username, password); err != nil {
			http.Error(w, "Error registering user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Redirect to login page after successful registration
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

// Add middleware to check if user is authenticated
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		auth, ok := session.Values["authenticated"].(bool)

		if !ok || !auth {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// Logout handler
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	// Revoke users authentication
	session.Values["authenticated"] = false
	session.Values["username"] = ""
	session.Options.MaxAge = -1 // Delete the cookie

	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// New groupchatPageHandler for group chats
func groupchatPageHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	username := session.Values["username"].(string)

	// Get user's ID
	userID, err := getUserID(username)
	if err != nil {
		fmt.Println("Error getting user ID:", err)
		http.Error(w, "Error getting user ID", http.StatusInternalServerError)
		return
	}

	// Get selected group from query params
	selectedGroupID := r.URL.Query().Get("group")

	// Check if the user is a member of the selected group
	var isMember bool
	if selectedGroupID != "" {
		err = db.QueryRow(`
			SELECT COUNT(*) > 0 
			FROM group_members 
			WHERE user_id = ? AND group_id = ?`, userID, selectedGroupID).Scan(&isMember)
		if err != nil {
			fmt.Println("Error checking group membership:", err)
			http.Error(w, "Error checking group membership", http.StatusInternalServerError)
			return
		}
	} else {
		isMember = false // No group selected, so the user is not a member
	}

	if !isMember && selectedGroupID != "" {
		// Redirect to the main group chat page or another appropriate page
		http.Redirect(w, r, "/groupchat", http.StatusSeeOther)
		return
	}

	// Prepare to get the group name only if a group is selected
	var groupName string
	if selectedGroupID != "" {
		err = db.QueryRow(`
			SELECT name 
			FROM groups 
			WHERE id = ?`, selectedGroupID).Scan(&groupName)
		if err != nil {
			fmt.Println("Error retrieving group name:", err)
			http.Error(w, "Error retrieving group name", http.StatusInternalServerError)
			return
		}
	}

	// Prepare to get all groups the user is a member of
	rows, err := db.Query(`
		SELECT g.id, g.name 
		FROM groups g
		JOIN group_members gm ON g.id = gm.group_id
		WHERE gm.user_id = ?
		ORDER BY g.created_at DESC`, userID)
	if err != nil {
		fmt.Println("Error querying groups:", err)
		http.Error(w, "Error querying groups", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Group struct {
		ID   int
		Name string
	}

	var groups []Group
	for rows.Next() {
		var group Group
		if err := rows.Scan(&group.ID, &group.Name); err != nil {
			fmt.Println("Error scanning group:", err)
			http.Error(w, "Error scanning group", http.StatusInternalServerError)
			return
		}
		groups = append(groups, group)
	}

	// Get messages for the selected group
	var messages []struct {
		Sender    string
		Content   template.HTML
		Timestamp string
	}

	if selectedGroupID != "" {
		rows, err = db.Query(`
			SELECT u.username, m.content, m.timestamp 
			FROM messages m
			JOIN users u ON m.sender_id = u.id
			WHERE m.group_id = ?
			ORDER BY m.timestamp`, selectedGroupID)
		if err != nil {
			fmt.Println("Error querying messages:", err)
			http.Error(w, "Error querying messages", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var msg struct {
				Sender    string
				Content   template.HTML
				Timestamp string
			}
			var content string
			if err := rows.Scan(&msg.Sender, &content, &msg.Timestamp); err != nil {
				fmt.Println("Error scanning message:", err)
				http.Error(w, "Error scanning message", http.StatusInternalServerError)
				return
			}
			// Sanitize the HTML content while preserving allowed formatting
			sanitized := sanitizer.SanitizeBytes([]byte(html.UnescapeString(content)))
			msg.Content = template.HTML(sanitized)
			messages = append(messages, msg)
		}
	}

	// Get all users for group creation
	allUsers := []string{}
	userRows, err := db.Query("SELECT username FROM users")
	if err != nil {
		fmt.Println("Error querying users:", err)
		http.Error(w, "Error querying users", http.StatusInternalServerError)
		return
	}
	defer userRows.Close()

	for userRows.Next() {
		var user string
		if err := userRows.Scan(&user); err != nil {
			fmt.Println("Error scanning user:", err)
			http.Error(w, "Error scanning user", http.StatusInternalServerError)
			return
		}
		if user != username {
			allUsers = append(allUsers, user)
		}
	}

	// Prepare GroupMembers
	var groupMembers []string
	if isMember {
		// If the user is a member, get the group members
		memberRows, err := db.Query(`
			SELECT u.username 
			FROM users u
			JOIN group_members gm ON u.id = gm.user_id
			WHERE gm.group_id = ?`, selectedGroupID)
		if err != nil {
			fmt.Println("Error querying group members:", err)
			http.Error(w, "Error querying group members", http.StatusInternalServerError)
			return
		}
		defer memberRows.Close()

		for memberRows.Next() {
			var member string
			if err := memberRows.Scan(&member); err != nil {
				fmt.Println("Error scanning group member:", err)
				http.Error(w, "Error scanning group member", http.StatusInternalServerError)
				return
			}
			groupMembers = append(groupMembers, member)
		}
	} else {
		// If the user is not a member, pass an empty list
		groupMembers = []string{}
	}

	// Render the template with the groups, messages, all users, and group members
	tmpl, err := template.ParseFiles("../static/groupchat/index.html")
	if err != nil {
		fmt.Println("Error loading template:", err)
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	data := struct {
		Username string
		Groups   []Group
		Messages []struct {
			Sender    string
			Content   template.HTML
			Timestamp string
		}
		SelectedGroupID   string
		SelectedGroupName string   // Add the group name
		Notification      string   // Add a notification field
		AllUsers          []string // Include all users for group creation
		GroupMembers      []string // Include group members
	}{
		Username:          username,
		Groups:            groups,
		Messages:          messages,
		SelectedGroupID:   selectedGroupID,
		SelectedGroupName: groupName,    // Pass the group name to the template
		Notification:      "",           // Default to empty
		AllUsers:          allUsers,     // Pass all users to the template
		GroupMembers:      groupMembers, // Pass group members to the template
	}

	if !isMember {
		data.Notification = "You are not a member of this group."
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		fmt.Println("Error executing template:", err)
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		return
	}
}

// Add new handler for sending group messages
func sendGroupMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, _ := store.Get(r, "session-name")
	username := session.Values["username"].(string)

	senderID, err := getUserID(username)
	if err != nil {
		http.Error(w, "Error getting user ID", http.StatusInternalServerError)
		return
	}

	r.ParseForm()
	groupID := r.FormValue("group_id")
	content := r.FormValue("content")

	// Check if the user is a member of the group
	var isMember bool
	err = db.QueryRow(`
		SELECT COUNT(*) > 0 
		FROM group_members 
		WHERE user_id = ? AND group_id = ?`, senderID, groupID).Scan(&isMember)
	if err != nil {
		http.Error(w, "Error checking group membership", http.StatusInternalServerError)
		return
	}

	if !isMember {
		http.Error(w, "You are not a member of this group", http.StatusForbidden)
		return
	}

	// Sanitize the HTML content before saving
	content = string(sanitizer.SanitizeBytes([]byte(content)))

	// Insert the message into the database
	_, err = db.Exec(
		"INSERT INTO messages (sender_id, group_id, content) VALUES (?, ?, ?)",
		senderID, groupID, content)
	if err != nil {
		http.Error(w, "Error saving message: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect back to the group chat page
	http.Redirect(w, r, "/groupchat?group="+groupID, http.StatusSeeOther)
}

// Add new handler for creating groups
func createGroupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, _ := store.Get(r, "session-name")
	username := session.Values["username"].(string)

	r.ParseForm()
	groupName := r.FormValue("group_name")
	members := r.Form["members"] // This will get all selected members

	// Add the current user to the members list
	if !slices.Contains(members, username) {
		members = append(members, username)
	}

	// Create the group using the updated getOrCreateChatGroup function
	groupID, err := getOrCreateChatGroup(groupName, members...)
	if err != nil {
		fmt.Println("Error creating group:", err, groupID)
		http.Error(w, "Error creating group: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect back to the newly created group chat page
	http.Redirect(w, r, fmt.Sprintf("/groupchat?group=%d", groupID), http.StatusSeeOther)
}

// Debug handler to return all database contents
func debugDatabaseHandler(w http.ResponseWriter, r *http.Request) {
	// Set JSON content type
	w.Header().Set("Content-Type", "application/json")

	debug := struct {
		Users    []DebugUser    `json:"users"`
		Groups   []DebugGroup   `json:"groups"`
		Messages []DebugMessage `json:"messages"`
	}{}

	// Get all users
	rows, err := db.Query("SELECT id, username, password_hash FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var user DebugUser
		if err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		debug.Users = append(debug.Users, user)
	}

	// Get all groups
	rows, err = db.Query("SELECT id, name, created_at FROM groups")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var group DebugGroup
		if err := rows.Scan(&group.ID, &group.Name, &group.CreatedAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		debug.Groups = append(debug.Groups, group)
	}

	// Get all messages
	rows, err = db.Query("SELECT id, sender_id, group_id, content, timestamp FROM messages")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var msg DebugMessage
		if err := rows.Scan(&msg.ID, &msg.Sender, &msg.GroupID, &msg.Content, &msg.Timestamp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		debug.Messages = append(debug.Messages, msg)
	}

	// Marshal and write the JSON response
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "    ") // Pretty print the JSON
	if err := encoder.Encode(debug); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func main() {
	// Initialize the database connection and create table if needed
	initDB()
	defer db.Close()

	// Serve static files (CSS and JS) from the ../static/ folder
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("../static/"))))

	// Route for root (/) redirects to groupchat page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/groupchat", http.StatusSeeOther)
		} else {
			http.NotFound(w, r)
		}
	})

	// Route for login page
	http.HandleFunc("/login", loginPageHandler)

	// Route for register page
	http.HandleFunc("/register", registerPageHandler)

	// Route for logout
	http.HandleFunc("/logout", logoutHandler)

	// Route for group chat page (now the main chat interface)
	http.HandleFunc("/groupchat", requireAuth(groupchatPageHandler))

	// Route for sending group messages
	http.HandleFunc("/send-group-message", requireAuth(sendGroupMessageHandler))

	// Route for creating new groups
	http.HandleFunc("/create-group", requireAuth(createGroupHandler))

	// Debug route - only available in development
	if true { // Change this condition for production
		http.HandleFunc("/debug/db", debugDatabaseHandler)
	}

	// Start the server on port 8080
	log.Println("Starting server on :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
