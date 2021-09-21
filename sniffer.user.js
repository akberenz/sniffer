/*!
// ==UserScript==
// @name         Steamgifts Secret Sniffer
// @namespace    https://github.com/bberenz/sniffer
// @description  Sniff out hidden content on steamgifts.com posts
// @icon         https://raw.githubusercontent.com/bberenz/sniffer/master/secret-agent.png
// @include      *://*.steamgifts.com/*
// @version      1.1.8.3
// @downloadURL  https://raw.githubusercontent.com/bberenz/sniffer/master/sniffer.user.js
// @updateURL    https://raw.githubusercontent.com/bberenz/sniffer/master/sniffer.meta.js
// @require      https://code.jquery.com/jquery-1.12.3.min.js
// @require      https://greasemonkey.github.io/gm4-polyfill/gm4-polyfill.js
// @grant        GM_addStyle
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM.getValue
// @grant        GM.setValue
// ==/UserScript==
*/

//  SETUP  //
const OPTIONS = {
  pinned: { key: "pinned", value: false, text: "Keep Pinned" },
  alwaysAll: { key: "alwaysAll", value: false, text: "Always Show All" }
};

const BELIEFS = [
  { style: "suspicion_none", wording: "Dubious suspicion" },
  { style: "suspicion_low", wording: "Possible suspicion" },
  { style: "suspicion_med", wording: "Moderate suspicion" },
  { style: "suspicion_high", wording: "High suspicion" }
];

const MORSE_MAP = {
  "·-": "A", "-···": "B", "-·-·": "C", "-··": "D", "·": "E", "··-·": "F", "--·": "G", "····": "H", "··": "I", "·---": "J", "-·-": "K", "·-··": "L", "--": "M",
  "-·": "N", "---": "O", "·--·": "P", "--·-": "Q", "·-·": "R", "···": "S", "-": "T", "··-": "U", "···-": "V", "·--": "W", "-··-": "X", "-·--": "Y", "--··": "Z",
  "-----": "0", "·----": "1", "··---": "2", "···--": "3", "····-": "4", "·····": "5", "-····": "6", "--···": "7", "---··": "8", "----·": "9",
  "·-·-·-": ".", "--··--": ",", "··--··": "?", "-····-": "-", "-···-": "=", "---···": ":", "·-·-·": "+", "-··-·": "/",
  "-·--·": "(", "-·--·-": ")", "··--·-": "_", "---·": "!", "-·-·--": "!", ".-.-..": "\n", "/": " "
};

const GENETIC_MAP = {
  "GGG": "G", "GGA": "G", "GGC": "G", "GGU": "G", "GAG": "E", "GAA": "E", "GAC": "D", "GAU": "D",
  "GCG": "A", "GCA": "A", "GCC": "A", "GCU": "A", "GUG": "V", "GUA": "V", "GUC": "V", "GUU": "V",
  "AGG": "R", "AGA": "R", "AGC": "S", "AGU": "S", "AAG": "K", "AAA": "K", "AAC": "N", "AAU": "N",
  "ACG": "T", "ACA": "T", "ACC": "T", "ACU": "T", "AUG": "M", "AUA": "I", "AUC": "I", "AUU": "I",
  "CGG": "R", "CGA": "R", "CGC": "R", "CGU": "R", "CAG": "Q", "CAA": "Q", "CAC": "H", "CAU": "H",
  "CCG": "P", "CCA": "P", "CCC": "P", "CCU": "P", "CUG": "L", "CUA": "L", "CUC": "L", "CUU": "L",
  "UGG": "W", "UGA": "*", "UGC": "C", "UGU": "C", "UAG": "*", "UAA": "*", "UAC": "Y", "UAU": "Y",
  "UCG": "S", "UCA": "S", "UCC": "S", "UCU": "S", "UUG": "L", "UUA": "L", "UUC": "F", "UUU": "F"
};

const Found = {
  HIDDEN: {
    _name: "hidden",
    HOVER: { _name: "hover", weight: 0, category: "HIDDEN", detail: "Shown on image hover:" },
    NULL_ELM: { _name: "nullElm", weight: 1, category: "HIDDEN", detail: "Declared on hidden elements:" },
    YOUTUBE: { _name: "youtubeParam", weight: 1, category: "HIDDEN", detail: "Hidden in a youtube link:" },
  },
  SUSPICIOUS: {
    _name: "suspicious",
    GIBBERISH: { _name: "gibberish", weight: 0, category: "SUSPICIOUS", detail: "Potentially useful text:" },
    LOCATION: { _name: "location", weight: -1, category: "SUSPICIOUS", detail: "Located under topic:" },
    OBSCURED: { _name: "obscured", weight: 1, category: "SUSPICIOUS", detail: "Potentially obscured link:" },
    SINGULAR: { _name: "singular", weight: 0, category: "SUSPICIOUS", detail: "Individually marked:", format: "$1 " },
    GROUPED: { _name: "grouped", weight: 1, category: "SUSPICIOUS", detail: "First characters from grouped lines:" }
  },
  DECODED: {
    _name: "decoded",
    ASCII: { _name: "decodedAscii", weight: 1, category: "DECODED", detail: "Decoded from ascii numbers:" },
    BASE64: { _name: "decodedBase64", weight: 1, category: "DECODED", detail: "Decoded from a base64 string:" },
    BINARY: { _name: "decodedBinary", weight: 1, category: "DECODED", detail: "Decoded from a binary sequence:" },
    GENETIC: { _name: "decodedGenetic", weight: 1, category: "DECODED", detail: "Decoded from a genetic sequence:" },
    HEX: { _name: "decodedHex", weight: 1, category: "DECODED", detail: "Decoded from a hex sequence:" },
    MORSE: { _name: "decodedMorse", weight: 1, category: "DECODED", detail: "Decoded from morse code sequence:" }
  },
  SEQUENCE: {
    _name: "sequence",
    BASE64: { _name: "base64", weight: 0, category: "SEQUENCE", detail: "Looks base64 encoded:" },
    BINARY: { _name: "binary", weight: 0, category: "SEQUENCE", detail: "Looks like binary code:" },
    DECIMAL: { _name: "decimal", weight: 0, category: "SEQUENCE", detail: "Looks like a decimal sequence:" },
    GENETIC: { _name: "genetic", weight: 0, category: "SEQUENCE", detail: "Looks like a genetic sequence:" },
    GIFT: { _name: "gift", weight: 3, category: "SEQUENCE", detail: "Looks like a giveaway code:", format: "<a href='/giveaway/$1/' target='_blank'>$1</a><hr/>" },
    GIFT_LINK: { _name: "giftLink", weight: 3, category: "SEQUENCE", detail: "Giveaway links:", format: "<a href='$1' target='_blank'>$1</a><hr/>" },
    IMGUR: { _name: "imgur", weight: 1, category: "SEQUENCE", detail: "Looks like an Imgur image code:", format: "<a href='http://imgur.com/$1' target='_blank'>$1</a><hr/>" },
    LINK: { _name: "link", weight: 2, category: "SEQUENCE", detail: "Secret links:", format: "<a href='$1' target='_blank'>$1</a><hr/>" },
    MORSE: { _name: "morse", weight: 0, category: "SEQUENCE", detail: "Looks like morse code:" },
    EXTERNAL: {
      _name: "external", weight: 2, category: "SEQUENCE", detail: "Looks like a puzzle code (ITH/Jig):",
      format: "<div>$1 <span style='float:right;'>" +
        "<a class='fa fa-question-circle-o' title='ItsTooHard' href='http://itstoohard.com/puzzle/$1' target='_blank'></a> / " +
        "<a class='fa fa-puzzle-piece' title='Jigidi' href='https://www.jigidi.com/jigsaw-puzzle/$1' target='_blank'></a>" +
        "</span></div> <div style='clear:both;'></div>"
    },
    UUID: { _name: "uuid", weight: 0, category: "SEQUENCE", detail: "Looks like SGTools code:", format: "<a href='https://www.sgtools.info/giveaways/$1' target='_blank'>$1</a><hr/>" }
  },
  PARTIAL: {
    _name: "partial",
    GIFT: { _name: "giftPart", weight: 2, category: "PARTIAL", detail: "Looks like a partial giveaway code:" },
    IMGUR: { _name: "imgurPart", weight: 1, category: "PARTIAL", detail: "Looks like a partial Imgur image code:" },
    EXTERNAL: { _name: "externalPart", weight: 2, category: "PARTIAL", detail: "Looks like a partial puzzle code (ITH/Jig):" },
  }
};

const findings = {};

function addFinding(foundList, postId, sort, value) {
  const category = Found[sort.category]._name;
  const type = sort._name;

  if (!foundList[postId]) { foundList[postId] = {}; }
  if (!foundList[postId][category]) { foundList[postId][category] = {}; }
  if (!foundList[postId][category][type]) { foundList[postId][category][type] = []; }

  const foundArr = foundList[postId][category][type];

  if (Array.isArray(value)) {
    foundList[postId][category][type] = foundArr.concat(value);
  } else {
    foundArr.push(value);
  }
}

// // // // //

/* Return altered strings */
const perform = {
  rotN: function(string, N) {
    return string.replace(/[A-Za-z]/g, function(c) {
      return String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + N) ? c : c - 26);
    });
  },

  scriptDecode: function(string) {
    const base = 16;
    const rotAt = 10;
    const substitute = perform.rotN("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 13);
    let rot = 13;
    let encoded = string.split("-");

    encoded.shift(); //first value not used in decryption
    if (encoded.length == 1) {
      const reset = [];
      $.each(encoded[0].split(""), function(i, ltr) {
        const idx = substitute.indexOf(ltr);
        if (~idx) {
          reset.push(idx);
        } else {
          reset.push(ltr);
        }
      });

      if (reset.length > rotAt) {
        rot = substitute.length - parseInt(reset.splice(rotAt).join(""), base);
      }

      encoded = reset.join("").match(/.{2}/g);
    }

    for (let i = 0; i < encoded.length; i++) {
      encoded[i] = String.fromCharCode(parseInt(encoded[i], base));
    }

    return perform.rotN(encoded.join(""), rot);
  }
};

/* Return boolean if match */
const checkIf = {
  nonsense: function(string) {
    let vowels = 1;
    let consonants = 1;
    let variety = "";

    if (string) {
      if (string.search(/\.com\b/) > -1) { return false; }

      for (let i = 0; i < string.length && variety.length < 21; i++) {
        const character = string.charAt(i).toLowerCase();

        if ((/[aeiou]/).test(character)) {
          vowels++;
        } else if ((/[bcdfghjklmnpqrstvwxyz]/).test(character)) {
          consonants++;
          if (variety.indexOf(character) == -1) {
            variety += character;
          }
        }
      }

      const ratio = vowels / (consonants + vowels);
      const diversity = variety.length / consonants;

      return ((ratio < 0.2 || ratio > 0.6) || (variety.length > 1 && diversity < 0.30) || string.match(/[a-z]*?\d+[a-z]*?/i));
    }

    return false;
  },

  visible: function(string) {
    // valid, visible ascii only
    return !!string.match(/^[\x20-\x7E\r\n]+$/);
  },

  _measure: document.createElement("canvas").getContext("2d"),
  small: function(string) {
    return checkIf.singular(string) && checkIf._measure.measureText(string).width < 6;
  },

  singular: function(string) {
    return string.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, "_").length == 1;
  },

  newSet: function($doc, postId) {
    return !((postId !== "undefined" && !$doc.find("[id='" + postId + "']").length)
      || (postId === "undefined" && !$doc.find("header").length)); //special case for root post
  },

  partial: function(string) {
    return !!string.match(/[^0-9a-z]/gi);
  }
};

/* Check for and record if match */
const lookFor = {
  anything: function(findings, postId, $elm) {
    lookFor.anchor(findings, postId, $elm);
    lookFor.imageText(findings, postId, $elm);
    lookFor.groupedLines(findings, postId, $elm);
    lookFor.formatted(findings, postId, $elm);
    lookFor.obscured(findings, postId, $elm.text());
    lookFor.morse(findings, postId, $elm.text());
    lookFor.genetic(findings, postId, $elm.text());
    lookFor.binary(findings, postId, $elm.text());
    lookFor.decimal(findings, postId, $elm.text());
    lookFor.base64(findings, postId, $elm.text());
    lookFor.uuid(findings, postId, $elm.text());
  },

  topic: function(finds) {
    const topic = $('[data-category-id="8"].is-selected').first().text().trim();
    if (topic.toLowerCase().indexOf("puzzle") > -1) { addFinding(finds, undefined, Found.SUSPICIOUS.LOCATION, topic); }
  },

  anchor: function(finds, postId, $elm) {
    if ($elm.length && $elm.is("a")) {
      const href = $elm.attr("href");

      if (!$elm.html() || checkIf.small($elm.text())) {
        if (href) { addFinding(finds, postId, Found.HIDDEN.NULL_ELM, href); }
      } else if (href.search(/youtube\.com/) > -1 || href.search(/youtu\.be/) > -1) {
        const expected = ["v", "t", "list", "feature", "index"]; //valid YT params
        const query = href.substring(href.indexOf("?")).split(/[?&]/);

        for (let param of query) {
          const bits = param.split(/=/);

          if (bits.length == 2) {
            if (expected.indexOf(bits[0]) == -1) {
              addFinding(finds, postId, Found.HIDDEN.YOUTUBE, bits[1]);
            }
          } else if (bits.length > 2) {
            addFinding(finds, postId, Found.HIDDEN.YOUTUBE, bits[2]);
          }
        }
      } else {
        //not a hidden link, but check if it's location is useful
        lookFor.length(finds, postId, href);
      }
    }
  },

  formatted: function(finds, postId, $elm) {
    if ($elm.is("strong") || $elm.is("em") || $elm.is("code") || $elm.hasClass("spoiler")) {
      lookFor.singles(finds, postId, $elm.text());
    }
  },

  imageText: function(finds, postId, $elm) {
    if ($elm.length && $elm.is("img")) {
      const title = $elm.attr("title");
      if (title) {
        addFinding(finds, postId, Found.HIDDEN.HOVER, title);
        lookFor.gibberish(finds, postId, title);
      }
    }
  },

  groupedLines: function(finds, postId, $elm) {
    if ($elm.is("p")) {
      const lines = $elm.find("br").length + 1;

      if (lines == 5 || lines == 8) {
        const group = $elm.text().split("\n");
        const firsts = [];
        let reasonable = true;

        //if text is in another element - don't count it
        $.each($elm.children(), function(i, elm) {
          if ($(elm).text()) { reasonable = false; }
        });

        for (let line of group) {
          if (line.length < 100) {
            firsts.push(line[0]);
          } else {
            reasonable = false;
          }
        }

        const seq = firsts.join("");

        if (checkIf.partial(seq)) {
          reasonable = false;
        }

        if (reasonable) {
          addFinding(finds, postId, Found.SUSPICIOUS.GROUPED, seq);
        }
      }
    }
  },

  singles: function(finds, postId, string) {
    if (!string) { return; }

    //single letters
    if (checkIf.singular(string) && string.match(/[A-Za-z0-9]/)) {
      addFinding(finds, postId, Found.SUSPICIOUS.SINGULAR, string);
    }
  },

  combiningSingular: function(finds, postId, string) {
    if (!string) { return; }

    const combining = string.replace(/\u1F600-\u1F64F/g, "").match(/[\u0000-\u007F](?=[\u0300-\u036F\u1AB0-\u1AFF\u1DC0-\u1DFF\u200E\u202A-\u202E\u20D0-\u20FF\uFE20-\uFE2F])/g);
    if (combining && combining.join("").trim().length) {
      addFinding(finds, postId, Found.SUSPICIOUS.SINGULAR, combining);
    }
  },

  obscured: function(finds, postId, string) {
    if (!string) { return; }

    const seq = string.match(/\b\w{4,5}:\/\/.+?(\s|$)/g);
    if (seq) {
      for (let match of seq) {
        if (match.toLowerCase().indexOf("http") === -1) {
          addFinding(finds, postId, Found.SUSPICIOUS.OBSCURED, match);
        }
      }
    }
  },

  gibberish: function(finds, postId, string) {
    if (!string) { return; }

    const seq = string.match(/(^|\s)\w{5,8}(\s|$)/g);
    if (seq) {
      for (let match of seq) {
        const at = match.trim();
        if (at.length != 6 && checkIf.nonsense(at) && !at.match(/^\d+$/)) {
          addFinding(finds, postId, Found.SUSPICIOUS.GIBBERISH, at);
        }
      }
    }
  },

  morse: function(finds, postId, string) {
    if (!string) { return; }

    const seq = string.match(/[\s\\\/.·*_−-]*[.·*_−-]{3,}[\s\\\/.·*_-]*/g);
    if (seq) {
      for (let match of seq) {
        const at = match.replace(/[.·*]/g, "·").replace(/[_−-]/g, "-").replace(/\r?\n/g, "").trim();
        if (!at.match(/^·+$/) && !at.match(/^-+$/) && at !== '·-·' && at !== '-·-') {
          addFinding(finds, postId, Found.SEQUENCE.MORSE, at);

          //try to decode
          const letters = at.split(/\s+/g);

          let decode = "";
          for (let ltr of letters) {
            if (MORSE_MAP[ltr]) { decode += MORSE_MAP[ltr]; }
          }

          if (decode && decode.length > 3) {
            addFinding(finds, postId, Found.DECODED.MORSE, decode);
          }
        }
      }
    }
  },

  genetic: function(finds, postId, string) {
    if (!string) { return; }

    const seq = string.match(/\b((?:[acguACGU]{3}|\d+)(?:\s+|\b|$)){3,}/g);
    if (seq) {
      for (let match of seq) {
        const at = match.trim();
        if (at.toUpperCase() !== "AAA" && at.toUpperCase() !== "GAA" && at.replace(/\d+/g, '').trim()) {
          addFinding(finds, postId, Found.SEQUENCE.GENETIC, at);

          //try to decode
          const letters = at.split(/\s+/g);

          let decode = "";
          for (let ltr of letters) {
            const mapped = GENETIC_MAP[ltr.toUpperCase()];

            if (mapped) {
              // first letter in each trio decides case
              const first = ltr[0];

              if (first.toUpperCase() === first) {
                decode += mapped;
              } else {
                decode += mapped.toLowerCase();
              }
            } else if (parseInt(ltr)) {
              decode += ltr;
            }
          }

          if (decode && decode.length > 3) {
            addFinding(finds, postId, Found.DECODED.GENETIC, decode);
          }
        }
      }
    }
  },

  binary: function(finds, postId, string) {
    if (!string) { return; }

    const seq = string.match(/([01\s]{8,})+/g);
    if (seq) {
      const each = seq.join("").replace(/\s+/g, "").match(/([01]{8})/g);
      if (!each) { return; }

      let complete = "";
      let decoded = "";

      for (let match of each) {
        if (match) {
          complete += match;
          decoded += String.fromCharCode(parseInt(match, 2));
        }
      }

      if (decoded && checkIf.visible(decoded)) {
        addFinding(finds, postId, Found.SEQUENCE.BINARY, complete);
        addFinding(finds, postId, Found.DECODED.BINARY, decoded);
      }
    }
  },

  hex: function(finds, postId, string) {
    if (!string) { return; }

    const seq = string.toUpperCase().match(/([0-9A-F\s]{8,})+/g);
    if (seq) {
      const each = seq.join("").replace(/\s+/g, "").match(/([0-9A-F]{2})/g);
      if (!each) { return; }

      let decode = "";
      for (let match of each) {
        if (match) { decode += String.fromCharCode(parseInt(match, 16)); }
      }

      if (decode && checkIf.visible(decode)) {
        addFinding(finds, postId, Found.DECODED.HEX, decode);
      }
    }
  },

  ascii: function(finds, postId, string) {
    if (!string) { return; }

    const seq = string.toUpperCase().match(/([0-9\s]{8,})+/g);
    if (seq) {
      const each = seq.join("").match(/([0-9]{2,3}\s?)/g);
      if (!each) { return; }

      let decode = "";
      for (let match of each) {
        if (match) { decode += String.fromCharCode(parseInt(match, 10)); }
      }

      if (decode && checkIf.visible(decode)) {
        addFinding(finds, postId, Found.DECODED.ASCII, decode);
      }
    }
  },

  decimal: function(finds, postId, string) {
    if (!string) { return; }

    const seq = string.match(/(\b[\dA-Fa-f]+\b(\s+|$)){3,}/g);
    if (seq) {
      addFinding(finds, postId, Found.SEQUENCE.DECIMAL, seq);

      lookFor.hex(finds, postId, string);
      lookFor.ascii(finds, postId, string);
    }
  },

  base64: function(finds, postId, string) {
    if (!string) { return; }

    const seq = string.match(/\b[A-Za-z0-9+\/]{6,}={0,2}(?:\s|$)/g);
    if (seq) {
      for (let match of seq) {
        try {
          const decode = atob(match);
          if (match.trim().length % 4 === 0 && checkIf.visible(decode)) {
            addFinding(finds, postId, Found.SEQUENCE.BASE64, match);
            addFinding(finds, postId, Found.DECODED.BASE64, decode);
          }
        } catch (ignore) { }
      }
    }
  },

  uuid: function(finds, postId, string) {
    if (!string) { return; }

    const seq = string.match(/\b[0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12}/gi);
    if (seq) {
      for (let match of seq) {
        addFinding(finds, postId, Found.SEQUENCE.UUID, match);
      }
    }
  },

  link: function(finds, postId, string) {
    if (!string) { return; }

    const testString = string.toLowerCase();
    if (testString.search(/giveaway\/\w{5}\//) > -1 || testString.search(/giveaways\/\w{8}-/) > -1) {
      addFinding(finds, postId, Found.SEQUENCE.GIFT_LINK, string);
    } else if (testString.indexOf("http") === 0 && testString.length > 8) {
      addFinding(finds, postId, Found.SEQUENCE.LINK, string);
    }
  },

  length: function(finds, postId, string) {
    if (!string || string.length < 5 || !string.match(/^[\w+?-]+$/)) { return; }

    let category = "SEQUENCE";
    if (checkIf.partial(string)) {
      category = "PARTIAL";
    }

    if (string.length == 5) {
      addFinding(finds, postId, Found[category].GIFT, string);
    } else if (string.length == 7) {
      addFinding(finds, postId, Found[category].IMGUR, string);
    } else if (string.length == 8) {
      addFinding(finds, postId, Found[category].EXTERNAL, string);
    }

    if (string.indexOf("ESGST") == 0) {
      addFinding(finds, postId, Found.SEQUENCE.GIFT, perform.scriptDecode(string));
    }
  },

  lengthMod: function(finds, postId, string) {
    if (!string || string.length < 5 || !string.match(/^[\w+?-]+$/)) { return; }

    let sequence = [];
    if (string.length % 5 == 0) {
      sequence = string.match(/.{5}/g);
    } else if (string.length % 7 == 0) {
      sequence = string.match(/.{7}/g);
    } else if (string.length % 8 == 0) {
      sequence = string.match(/.{8}/g);
    }

    for (let match of sequence) {
      lookFor.length(finds, postId, match);
    }
  }
};

/* Pull text and test */
const actOn = {
  tags: function(postId, $parent) {
    $.each($parent.children(), function(idx, child) {
      try {
        const $child = $(child);

        //go straight to children for these tags
        if ($child.is("ul") || $child.is("ol") || $child.is("pre") || $child.is("blockquote")) {
          actOn.tags(postId, $child);
          return;
        }

        // search for something interesting
        lookFor.anything(findings, postId, $child);

        //continue on to children
        actOn.tags(postId, $child);
      } catch (e) { console.error(e); }
    });
  },

  page: function($doc) {
    $.each($doc.find(".markdown").not(".comments__entity__description"), function(idx, sniff) {
      try {
        const $sniff = $(sniff);
        const postId = $sniff.parents(".comment__summary").attr("id");

        actOn.tags(postId, $sniff);
        lookFor.combiningSingular(findings, postId, $sniff.text());
      } catch (e) { console.error(e); }
    });

    //check for possible sequences
    for (let postId in findings) {
      //if not in current doc, we've already ran this check
      if (!checkIf.newSet($doc, postId)) { continue; }

      if (findings.hasOwnProperty(postId)) {
        const findId = findings[postId];

        for (let category in findId) {
          if (category === Found.SEQUENCE._name) { continue; }

          if (findId.hasOwnProperty(category)) {
            const findCat = findId[category];

            for (let type in findCat) {
              if (type === Found.SUSPICIOUS.LOCATION._name) { continue; }

              if (findCat.hasOwnProperty(type)) {
                const findType = findCat[type];

                //group these up to check
                if (type === Found.SUSPICIOUS.SINGULAR._name) {
                  const joint = findType.join("");

                  lookFor.lengthMod(findings, postId, joint);
                  lookFor.link(findings, postId, joint);
                }

                //keep these separate to check
                for (let ftype of findType) {
                  if (type !== Found.HIDDEN.HOVER._name) {
                    lookFor.length(findings, postId, ftype);
                  }

                  lookFor.link(findings, postId, ftype);
                }
              }
            }
          }
        }
      }
    }
  },

  content: function($doc) {
    try {
      actOn.page($doc);
      visualize.icon($doc);
    } catch (e) { console.error(e); }
  }
};

// // // // //

/* Visual components */
const bits = {
  box: $("<div/>").addClass("suspicion__content")
    .html("<div class='suspicion__results__icons'>" +
      " <em id='suspect-main' class='fa fa-user-secret is-selected'></em>" +
      " <em id='suspect-input' class='fa fa-keyboard-o'></em>" +
      " <em id='suspect-setting' class='fa fa-gear pull-right'></em>" +
      "</div>" +
      "<div class='suspicion__results__outer-wrap'></div>"),
  content: null,
  input: $("<div/>").addClass("suspicion__results__inner-wrap")
    .html("<strong>Custom Input</strong>" +
      "<input class='form__input' type='text' placeholder='Suspicious Text' />" +
      "<hr class='split' />" +
      "<div class='suspicion__section'></div>"),
  opts: $("<div/>").addClass("suspicion__results__inner-wrap"), //filled when viewed

  focusOn: function($entity) {
    bits.box.find("#suspect-main").removeClass("is-selected");
    bits.box.find("#suspect-input").removeClass("is-selected");
    bits.box.find("#suspect-setting").removeClass("is-selected");

    $entity.addClass("is-selected");
  }
};

/* Setup injection onto page and control components */
const visualize = {
  style: function() {
    GM_addStyle("div.comment__secrets{ display: inline-block; cursor: pointer; margin-right: 6px; }" +
      ".suspicion_none{ color: #DDD; }" +
      ".suspicion_low { color: #BBB; }" +
      ".suspicion_med { color: #777; }" +
      ".suspicion_high{ color: #111; }" +
      ".suspicion__content{ background-color: #222; border: 1px solid #2D291F; border-radius: 4px; box-shadow: 4px 4px 7px #555; z-index: 1000; " +
      "                     display: none; position: absolute; max-width: 256px; padding: 5px; color: #B9A98F; word-wrap: break-word; }" +
      ".suspicion__results__icons{ border-bottom: 1px solid #FFF; display: flex; justify-content: space-between; padding-bottom: 4px; margin-bottom: 4px; }" +
      ".suspicion__results__icons .fa{ color: #FFF; opacity: 0.4; }" +
      ".suspicion__results__icons .fa.is-selected, .suspicion__content .form__checkbox .fa{ opacity: 1.0; }" +
      ".suspicion__content hr:not(.split){ border: 1px solid #333; border-top: none; margin: 0.15em; }" +
      ".suspicion__content div > hr:not(.split):last-of-type{ display: none; }" +
      ".suspicion__results__inner-wrap > .suspicion__section:not(:first-of-type){ margin-top: 0.5em; }" +
      ".suspicion__content strong{ color: #EDEBE5; }" +
      ".suspicion__content a, .suspicion__content a.fa{ color: #B99964; }" +
      ".suspicion__content a:hover, .suspicion__content a.fa:hover{ color: #B9780F; }" +
      ".suspicion__content a.local{ color: #B96464; }" +
      ".suspicion__content a.local:hover{ color: #B90F0F; }" +
      ".suspicion__content .form__checkbox{ color: inherit; justify-content: space-between; border-bottom: none; }");

    //color compatibility with dark theme
    if ($("body").css("background-color") !== "rgb(149, 164, 192)") {
      console.log("Assuming dark theme and adjusting colors");
      GM_addStyle(".suspicion_none{ color: #2E2E2C; }" +
        ".suspicion_low { color: #5C5C58; }" +
        ".suspicion_med { color: #B8B8B0; }" +
        ".suspicion_high{ color: #FFFFFF; }" +
        ".suspicion__content{ background-color: #f0f2f5; border: 1px solid #D2D6E0; color: #465670; }" +
        ".suspicion__results__icons .fa{ color: #000; }" +
        ".suspicion__results__icons{ border-bottom: 1px solid #000; }" +
        ".suspicion__content hr:not(.split){ border-color: #d0d2d5; }" +
        ".suspicion__content strong{ color: #12141A; }" +
        ".suspicion__content a, .suspicion__content a.fa{ color: #4B72D4; }" +
        ".suspicion__content a:hover, .suspicion__content a.fa:hover{ color: #8A9FD4; }" +
        ".suspicion__content a.local{ color: #AF4AD4; }" +
        ".suspicion__content a.local:hover{ color: #DAA6ED; }");
    }
  },

  reveal: function(elm, display) {
    const offset = $(elm).offset();
    const pad = 6;

    const $content = $("<div/>").addClass("suspicion__results__inner-wrap");
    for (let prime of display.primary) {
      $content.append(visualize.section(prime));
    }

    if (display.secondary.length) {
      const $more = $("<a/>").addClass("local").attr("href", "#").html("Show All Clues")
        .on("click", function(evt) {
          for (let second of display.secondary) {
            $content.append(visualize.section(second));
          }

          $(this).hide();
          evt.preventDefault();
        });

      $content.append("<hr class='split' />").append($more);

      if (OPTIONS.alwaysAll.value) { $more.click(); }
    }

    bits.content = $content;
    bits.box.css({ "display": "block", "top": Math.floor(offset.top - pad), "left": Math.floor(offset.left - pad) })
      .find(".suspicion__results__outer-wrap").html($content);
  },

  results: function(finds, postId) {
    //build display text from findings
    const display = { primary: [], secondary: [], raw: [], highest: -1 };

    for (let category in Found) {
      if (Found.hasOwnProperty(category) && finds[postId].hasOwnProperty(Found[category]._name)) {
        const findCat = Found[category];

        for (let type in findCat) {
          if (type === "_name") { continue; }

          if (findCat.hasOwnProperty(type) && finds[postId][findCat._name].hasOwnProperty(findCat[type]._name)) {
            const findType = findCat[type];
            const format = findType.format || "$1<hr/>";

            if (display.highest < findType.weight) {
              display.highest = findType.weight;
            }

            let content = "";
            for (let val of finds[postId][findCat._name][findType._name]) {
              content += format.replace(/\$1/g, val);
            }

            display.raw.push({
              title: findType.detail,
              content: content,
              weighs: findType.weight
            });
          }
        }
      }
    }

    for (let raw of display.raw) {
      if (raw.weighs == display.highest) {
        display.primary.push(raw);
      } else {
        display.secondary.push(raw);
      }
    }

    return display;
  },

  section: function(data) {
    return "<div class='suspicion__section'><strong>" + data.title + "</strong><br/>" + data.content + "</div>";
  },

  icon: function($doc) {
    //inject icon on scanned comments
    for (let postId in findings) {
      //if not in current doc, we've already added this
      if (!checkIf.newSet($doc, postId)) { continue; }

      if (findings.hasOwnProperty(postId)) {
        (function(_postId) {
          const display = visualize.results(findings, _postId);
          function byWeight(a, b) { return b.weighs - a.weighs; };

          display.primary.sort(byWeight);
          display.secondary.sort(byWeight);

          //make icon and append to post
          if (display.highest < 0) { display.highest = 0; }
          const $secret = $("<div/>").addClass("comment__secrets").addClass(BELIEFS[display.highest].style)
            .html("<em class='fa fa-user-secret' title='" + BELIEFS[display.highest].wording + "'></em>")
            .on('click', function() { visualize.reveal(this, display); return false; });

          if (_postId === "undefined") {
            const $base = $doc.find(".page__description__display-state");
            if ($base.length == 0) {
              $doc.find(".comment").first().find(".comment__actions").prepend($secret);
            } else {
              const $alt = $(".page__description__edit");
              if ($alt.length > 0) {
                $alt.before($secret);
              } else {
                $base.append($secret);
              }
            }
          } else {
            $doc.find("[id='" + _postId + "']").find(".comment__actions").prepend($secret);
          }
        })(postId);
      }
    }
  }
};

/* Kick off sniffing */
const init = {
  form: function() {
    const $box = bits.box;
    const $wrap = $box.find(".suspicion__results__outer-wrap");

    $box.find("#suspect-main").on("click", function() {
      const $this = $(this);
      if (!$this.hasClass("is-selected")) {
        bits.focusOn($this);

        $wrap.html(bits.content);

        //always all
        if (OPTIONS.alwaysAll.value) { $(".local").click(); }
      }
    });

    //going from this scren to main kills the "show all button"
    $box.find("#suspect-input").on("click", function() {
      const $this = $(this);
      if (!$this.hasClass("is-selected")) {
        bits.focusOn($this);

        bits.content.detach();
        $wrap.html(bits.input);

        let customFinds = {};
        const $results = $wrap.find(".suspicion__section");

        $wrap.find(".form__input").on("input", function() {
          //reset on every new input
          customFinds = {};
          $results.html("");

          const $content = $("<div/>").html($(this).val());
          const customId = "0";

          //find from new input
          lookFor.anything(customFinds, customId, $content);
          lookFor.lengthMod(customFinds, customId, $content.text());

          if (customFinds[customId]) {
            const customDisplay = visualize.results(customFinds, customId);

            for (let prime of customDisplay.primary) {
              $results.append(visualize.section(prime));
            }

            for (let second of customDisplay.secondary) {
              $results.append(visualize.section(second));
            }
          }
        });
      }
    });

    $box.find("#suspect-setting").on("click", function() {
      const $this = $(this);
      if (!$this.hasClass("is-selected")) {
        bits.focusOn($this);

        const wide = $wrap.find(".suspicion__results__inner-wrap").width();

        bits.content.detach();
        $wrap.html(bits.opts.css("width", wide));

        bits.opts.html("<strong>Options</strong>");
        $.each(OPTIONS, function(i, opt) {
          const $content = init.settingBlock(opt);
          bits.opts.append($content).append("<hr/>");
        });
      }
    });

    $("body").append($box);

    visualize.style();
    init.options();
  },

  settingBlock: function(setting) {
    const $content = $("<div/>").addClass("form__checkbox").append(setting.text)
      .append("<i class='form__checkbox__default fa fa-square-o'></i>")
      .append("<i class='form__checkbox__hover fa fa-square'></i>")
      .append("<i class='form__checkbox__selected fa fa-check-square'></i>");

    if (setting.value) { $content.addClass("is-selected"); }

    $content.on("click", function() {
      $content.toggleClass("is-selected");

      setting.value = !setting.value;
      GM.setValue(setting.key, setting.value).then(init.options);
    });

    return $content;
  },

  options: function() {
    const $box = bits.box;

    //pinned
    function turnOff() {
      $box.css({ "display": "none" }).find(".suspicion__results__outer-wrap").html("");
      bits.focusOn($box.find("#suspect-main"));

      //clear custom input
      bits.input.find("input").val("");
      bits.input.find(".suspicion__section").html("");
    };

    if (OPTIONS.pinned.value) {
      $box.off("mouseleave click").on("click", function(evt) { evt.stopPropagation(); });
      $("body").off("click").on("click", turnOff);
    } else {
      $box.off("mouseleave click").on('mouseleave', turnOff);
      $box.off("mouseleave click").on('mouseleave', function(evt) {
        // Chrome occasionally triggers mouseleave events when clicking
        const $hovering = $(document.elementFromPoint(evt.clientX, evt.clientY));
        if (!$hovering.hasClass("suspicion__content")) { $hovering = $hovering.parents(".suspicion__content"); }
        if (this === $hovering[0]) { return true; }

        turnOff();
      });
      $("body").off("click");
    }
  }
};

// // // // //

Promise.all([
  GM.getValue("pinned", false),
  GM.getValue("alwaysAll", false),
]).then(function(states) {
  OPTIONS.pinned.value = states[0];
  OPTIONS.alwaysAll.value = states[1];

  //one-time calls
  init.form();
  lookFor.topic(findings);

  //sniffer calls
  const $document = $(document);
  let originalContent = $(".comment");

  $document.on('scroll', function() {
    const currentContent = $(".comment");
    if (currentContent.length > originalContent.length) {
      actOn.content($(currentContent).not(originalContent));
      originalContent = currentContent;
    }
  });

  actOn.content($document); //inital page load
});
