import React from "react";
import ReactDOM from "react-dom";
import { Users } from "./users";

import "./styles/app.css";

const App = () => {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="max-w-3xl mx-auto">
        <div className="-ml-4 my-6 flex items-center justify-between flex-wrap sm:flex-nowrap">
          <div className="ml-4 mt-2">
            <h3 className="text-lg leading-6 font-medium text-gray-900">Users List</h3>
          </div>
          <div className="ml-4 mt-2 flex-shrink-0">
            <a
              href="/logout"
              type="button"
              className="relative inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
            >
              Logout
            </a>
          </div>
        </div>

        <Users />
      </div>
    </div>
  );
};

ReactDOM.render(<App />, document.getElementById("root"));
