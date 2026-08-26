import { useEffect, useState } from "react";
import { api } from "../api";

export default function Settings() {
  const [profileForm, setProfileForm] = useState({ name: "", email: "" });
  const [profileError, setProfileError] = useState("");
  const [profileSuccess, setProfileSuccess] = useState("");
  const [profileSubmitting, setProfileSubmitting] = useState(false);

  const [passwordForm, setPasswordForm] = useState({
    currentPassword: "",
    newPassword: "",
    confirmPassword: "",
  });
  const [passwordError, setPasswordError] = useState("");
  const [passwordSuccess, setPasswordSuccess] = useState("");
  const [passwordSubmitting, setPasswordSubmitting] = useState(false);

  useEffect(() => {
    api
      .profile()
      .then((data) => setProfileForm({ name: data.user.name, email: data.user.email }))
      .catch((err) => setProfileError(err.message));
  }, []);

  async function handleProfileSubmit(event) {
    event.preventDefault();
    setProfileError("");
    setProfileSuccess("");
    setProfileSubmitting(true);
    try {
      const data = await api.updateProfile(profileForm);
      setProfileSuccess(data.message);
    } catch (err) {
      setProfileError(err.message);
    } finally {
      setProfileSubmitting(false);
    }
  }

  async function handlePasswordSubmit(event) {
    event.preventDefault();
    setPasswordError("");
    setPasswordSuccess("");
    setPasswordSubmitting(true);
    try {
      const data = await api.changePassword(passwordForm);
      setPasswordSuccess(data.message);
      setPasswordForm({ currentPassword: "", newPassword: "", confirmPassword: "" });
    } catch (err) {
      setPasswordError(err.message);
    } finally {
      setPasswordSubmitting(false);
    }
  }

  return (
    <>
      <div className="topbar">
        <h1>Settings</h1>
      </div>

      <div className="row g-4">
        <div className="col-lg-6">
          <div className="card h-100">
            <h2 className="section-title">Account Details</h2>
            {profileError && <div className="alert alert-danger">{profileError}</div>}
            {profileSuccess && <div className="alert alert-success">{profileSuccess}</div>}
            <form onSubmit={handleProfileSubmit}>
              <div className="field">
                <label htmlFor="name">Full Name</label>
                <input
                  id="name"
                  value={profileForm.name}
                  onChange={(e) => setProfileForm((prev) => ({ ...prev, name: e.target.value }))}
                  required
                />
              </div>
              <div className="field">
                <label htmlFor="email">Email</label>
                <input
                  id="email"
                  type="email"
                  value={profileForm.email}
                  onChange={(e) => setProfileForm((prev) => ({ ...prev, email: e.target.value }))}
                  required
                />
              </div>
              <button className="btn btn-primary" type="submit" disabled={profileSubmitting}>
                {profileSubmitting ? "Saving..." : "Save Changes"}
              </button>
            </form>
          </div>
        </div>

        <div className="col-lg-6">
          <div className="card h-100">
            <h2 className="section-title">Change Password</h2>
            {passwordError && <div className="alert alert-danger">{passwordError}</div>}
            {passwordSuccess && <div className="alert alert-success">{passwordSuccess}</div>}
            <form onSubmit={handlePasswordSubmit}>
              <div className="field">
                <label htmlFor="currentPassword">Current Password</label>
                <input
                  id="currentPassword"
                  type="password"
                  value={passwordForm.currentPassword}
                  onChange={(e) =>
                    setPasswordForm((prev) => ({ ...prev, currentPassword: e.target.value }))
                  }
                  required
                />
              </div>
              <div className="field">
                <label htmlFor="newPassword">New Password</label>
                <input
                  id="newPassword"
                  type="password"
                  value={passwordForm.newPassword}
                  onChange={(e) =>
                    setPasswordForm((prev) => ({ ...prev, newPassword: e.target.value }))
                  }
                  required
                />
              </div>
              <div className="field">
                <label htmlFor="confirmPassword">Confirm New Password</label>
                <input
                  id="confirmPassword"
                  type="password"
                  value={passwordForm.confirmPassword}
                  onChange={(e) =>
                    setPasswordForm((prev) => ({ ...prev, confirmPassword: e.target.value }))
                  }
                  required
                />
              </div>
              <button className="btn btn-primary" type="submit" disabled={passwordSubmitting}>
                {passwordSubmitting ? "Updating..." : "Change Password"}
              </button>
            </form>
          </div>
        </div>
      </div>
    </>
  );
}
