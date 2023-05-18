import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import TileJournal from "./Tile";
import { createJournal } from "../api";
import { getUserJournals } from "../api";

export default function Home() {
  const [userInput, setUserInput] = useState("");
  const [journals, setJournals] = useState([]);
  const [errorMessage, setErrorMessage] = useState("");

  useEffect(() => {
    const userToken = localStorage.getItem("userToken");

    async function fetchData() {
      try {
        const userJournals = await getUserJournals(userToken);
        console.log("usrjournal",userJournals)
        setJournals(userJournals);
      } catch (error) {
        console.error(error);
        // Handle any errors that occurred during the retrieval of the journal entries
      }
    }

    fetchData();
  }, []); // Run this effect only once on mount

  const onUserChangedText = (event) => {
    setUserInput(event.target.value);
  };

  const handleSendClick = async (event) => {
    event.preventDefault();

    if (!userInput) {
      return;
    }

    const userToken = localStorage.getItem("userToken");

    try {
      const journalData = {
        content: userInput,
      };

      const createdJournal = await createJournal(journalData, userToken);

      // Insert the newly created journal at the beginning of the array of journals
      setJournals([createdJournal, ...journals]);

      // Reset the userInput state
      setUserInput("");
    } catch (error) {
      console.error(error);
        setErrorMessage(error.message);
      }
  };

  const journal =  journals.map((journal, index) => {
    return (
      <TileJournal
        key={journal.id}
        data={journal.content}
        position={index}
      />
    )
  })

  return (
    <>
      <div className="prompt-container">
        <h2>Write your journal in the box below to send anonymously</h2>
        {errorMessage && <h3 style={{color: 'red'}}>{errorMessage}</h3>}
        <textarea
          placeholder="maximum 500 characters"
          className="prompt-box"
          value={userInput}
          onChange={onUserChangedText}
          maxLength={500}
        />

        <div className="prompt-buttons">
          <button className="send-btn" onClick={handleSendClick}>Send</button>
        </div>
      </div>
      <div className="journal">
          {journal}
      </div>
    </>
  );
}
