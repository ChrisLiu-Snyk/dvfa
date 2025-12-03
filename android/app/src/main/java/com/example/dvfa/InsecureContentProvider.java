package com.example.dvfa;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.UriMatcher;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.database.sqlite.SQLiteQueryBuilder;
import android.net.Uri;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class InsecureContentProvider extends ContentProvider {

    private static final String TAG = "InsecureContentProvider";
    private static final String AUTHORITY = "com.example.dvfa.insecureprovider";
    private static final String USERS_TABLE = "users";
    public static final Uri CONTENT_URI = Uri.parse("content://" + AUTHORITY + "/" + USERS_TABLE);

    private static final int USERS = 1;
    private static final UriMatcher uriMatcher;

    static {
        uriMatcher = new UriMatcher(UriMatcher.NO_MATCH);
        uriMatcher.addURI(AUTHORITY, USERS_TABLE, USERS);
    }

    private SQLiteDatabase db;

    private static class DatabaseHelper extends SQLiteOpenHelper {
        private static final String DATABASE_NAME = "insecure_database.db";
        private static final int DATABASE_VERSION = 1;

        private static final String CREATE_DB_TABLE = " CREATE TABLE " + USERS_TABLE +
                " (id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                " username TEXT NOT NULL, " +
                " password TEXT NOT NULL);";

        public DatabaseHelper(Context context) {
            super(context, DATABASE_NAME, null, DATABASE_VERSION);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL(CREATE_DB_TABLE);
            // Insert some dummy data
            db.execSQL("INSERT INTO users (username, password) VALUES ('testuser', 'testpass')");
            db.execSQL("INSERT INTO users (username, password) VALUES ('admin', 'adminpass')");
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
            db.execSQL("DROP TABLE IF EXISTS " + USERS_TABLE);
            onCreate(db);
        }
    }

    @Override
    public boolean onCreate() {
        DatabaseHelper dbHelper = new DatabaseHelper(getContext());
        db = dbHelper.getWritableDatabase();
        return (db == null) ? false : true;
    }

    @Nullable
    @Override
    public Cursor query(@NonNull Uri uri, @Nullable String[] projection, @Nullable String selection,
                        @Nullable String[] selectionArgs, @Nullable String sortOrder) {
        SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
        qb.setTables(USERS_TABLE);

        switch (uriMatcher.match(uri)) {
            case USERS:
                // Vulnerability: SQL Injection (Content Provider)
                // The selection parameter is directly used without sanitization,
                // allowing for SQL injection if not properly handled by the caller.
                // In a real app, this should be validated or parameterized.
                Log.e(TAG, "Insecure query selection: " + selection);
                break;
            default:
                throw new IllegalArgumentException("Unknown URI " + uri);
        }

        Cursor c = qb.query(db, projection, selection, selectionArgs, null, null, sortOrder);
        c.setNotificationUri(getContext().getContentResolver(), uri);
        return c;
    }

    @Nullable
    @Override
    public String getType(@NonNull Uri uri) {
        switch (uriMatcher.match(uri)) {
            case USERS:
                return "vnd.android.cursor.dir/vnd.example.user";
            default:
                throw new IllegalArgumentException("Unsupported URI: " + uri);
        }
    }

    @Nullable
    @Override
    public Uri insert(@NonNull Uri uri, @Nullable ContentValues values) {
        // Not implemented for this vulnerability demo
        return null;
    }

    @Override
    public int delete(@NonNull Uri uri, @Nullable String selection, @Nullable String[] selectionArgs) {
        // Not implemented for this vulnerability demo
        return 0;
    }

    @Override
    public int update(@NonNull Uri uri, @Nullable ContentValues values, @Nullable String selection,
                      @Nullable String[] selectionArgs) {
        // Not implemented for this vulnerability demo
        return 0;
    }
}
