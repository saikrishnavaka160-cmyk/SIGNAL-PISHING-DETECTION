import {
  signInWithPopup,
  signOut,
  onAuthStateChanged,
  User,
  GoogleAuthProvider,
} from 'firebase/auth';
import { auth, googleAuthProvider } from '../lib/firebase';

// Memory-only access token storage (MANDATORY: Never stored in localStorage or sessionStorage)
let inMemoryAccessToken: string | null = null;

// Auth state listeners
type AuthListener = (user: User | null, token: string | null) => void;
const listeners = new Set<AuthListener>();

function notifyListeners(user: User | null) {
  listeners.forEach((listener) => {
    try {
      listener(user, inMemoryAccessToken);
    } catch (e) {
      console.error('Error in auth listener:', e);
    }
  });
}

// Automatically clear token if user signs out or session changes
onAuthStateChanged(auth, (user) => {
  if (!user) {
    inMemoryAccessToken = null;
  }
  notifyListeners(user);
});

export function getGoogleAccessToken(): string | null {
  return inMemoryAccessToken;
}

export function subscribeToAuth(listener: AuthListener): () => void {
  listeners.add(listener);
  // Send initial state
  listener(auth.currentUser, inMemoryAccessToken);
  return () => {
    listeners.delete(listener);
  };
}

export async function signInWithGoogle(): Promise<{ user: User; accessToken: string | null }> {
  try {
    const result = await signInWithPopup(auth, googleAuthProvider);
    const credential = GoogleAuthProvider.credentialFromResult(result);
    const token = credential?.accessToken || null;
    inMemoryAccessToken = token;
    notifyListeners(result.user);
    return { user: result.user, accessToken: token };
  } catch (error) {
    console.error('Sign-in failed:', error);
    throw error;
  }
}

export async function signOutGoogle(): Promise<void> {
  inMemoryAccessToken = null;
  await signOut(auth);
  notifyListeners(null);
}
