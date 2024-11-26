import React from 'react';

const ErrorPage = ({ code, title, message }) => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-black">
      <div className="max-w-md w-full space-y-8 bg-zinc-900 p-10 rounded-xl shadow-xl">
        <div className="text-center space-y-6">
          <div className="w-24 h-24 mx-auto bg-red-500/10 rounded-full flex items-center justify-center">
            <span className="text-4xl font-bold text-red-500">{code}</span>
          </div>
          
          <h2 className="text-2xl font-bold text-white">
            {title || 'Error'}
          </h2>
          
          <p className="text-zinc-400">
            {message}
          </p>
          
          <button 
            onClick={() => window.history.back()}
            className="px-4 py-2 bg-zinc-800 text-white rounded-lg hover:bg-zinc-700 transition-colors"
          >
            Go Back
          </button>
        </div>
      </div>
    </div>
  );
};

export default ErrorPage;
