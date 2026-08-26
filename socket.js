const jwt = require("jsonwebtoken");

function setupSocket(io) {
  // =====================================================
  // SOCKET AUTHENTICATION
  // =====================================================

  io.use((socket, next) => {
    try {
      const token =
        socket.handshake.auth?.token ||
        socket.handshake.headers?.authorization?.replace(
          "Bearer ",
          ""
        );

      if (!token) {
        return next(
          new Error("Authentication token required")
        );
      }

      if (!process.env.JWT_SECRET) {
        return next(
          new Error("JWT_SECRET is missing")
        );
      }

      const decoded = jwt.verify(
        token,
        process.env.JWT_SECRET
      );

      socket.user = {
        id: decoded.id,
        role: decoded.role,
      };

      next();
    } catch (error) {
      console.error(
        "SOCKET AUTH ERROR:",
        error.message
      );

      next(
        new Error(
          "Invalid or expired authentication token"
        )
      );
    }
  });

  // =====================================================
  // SOCKET CONNECTION
  // =====================================================

  io.on("connection", (socket) => {
    console.log("");
    console.log(
      "===================================="
    );
    console.log("🔌 SOCKET CONNECTED");
    console.log("Socket ID:", socket.id);
    console.log("User ID:", socket.user.id);
    console.log("Role:", socket.user.role);
    console.log(
      "===================================="
    );

    // ---------------------------------------------------
    // PERSONAL ROOM
    // ---------------------------------------------------

    socket.join(
      `user:${socket.user.id}`
    );

    // ---------------------------------------------------
    // MODERATOR ROOM
    // ---------------------------------------------------

    if (
      socket.user.role === "Moderator" ||
      socket.user.role === "Admin"
    ) {
      socket.join("moderators");
    }

    // ---------------------------------------------------
    // ADMIN ROOM
    // ---------------------------------------------------

    if (socket.user.role === "Admin") {
      socket.join("admins");
    }

    // ---------------------------------------------------
    // JOIN DASHBOARD ROOMS
    // ---------------------------------------------------

    socket.on(
      "join_dashboard",
      (dashboard) => {
        if (
          dashboard === "moderator" &&
          (
            socket.user.role === "Moderator" ||
            socket.user.role === "Admin"
          )
        ) {
          socket.join("moderators");

          console.log(
            `User ${socket.user.id} joined moderator dashboard`
          );
        }

        if (
          dashboard === "admin" &&
          socket.user.role === "Admin"
        ) {
          socket.join("admins");

          console.log(
            `User ${socket.user.id} joined admin dashboard`
          );
        }
      }
    );

    // ---------------------------------------------------
    // DISCONNECT
    // ---------------------------------------------------

    socket.on(
      "disconnect",
      (reason) => {
        console.log(
          "🔌 SOCKET DISCONNECTED:",
          socket.id,
          reason
        );
      }
    );
  });
}

module.exports = setupSocket;