/*!
// ==UserScript==
// @name         Steamgifts Secret Sniffer
// @namespace    https://github.com/bberenz/sniffer
// @description  Sniff out hidden content on steamgifts.com posts
// @icon         https://raw.githubusercontent.com/bberenz/sniffer/master/secret-agent.png
// @include      *://*.steamgifts.com/*
// @version      1.0.0
// @downloadURL  https://raw.githubusercontent.com/bberenz/sniffer/master/sniffer.user.js
// @updateURL    https://raw.githubusercontent.com/bberenz/sniffer/master/sniffer.meta.js
// @require      https://code.jquery.com/jquery-1.12.3.min.js
// @grant        GM_addStyle
// ==/UserScript==
*/

//  SETUP  //
var BELIEFS = [
  { style: "suspicion_none", wording: "Dubious suspicion" },
  { style: "suspicion_low", wording: "Possible suspicion" },
  { style: "suspicion_med", wording: "Moderate suspicion" },
  { style: "suspicion_high", wording: "High suspicion" }
];

var MORSE_MAP = {
  "·-":"A","-···":"B","-·-·":"C","-··":"D","·":"E","··-·":"F","--·":"G","····":"H","··":"I","·---":"J","-·-":"K","·-··":"L","--":"M",
  "-·":"N","---":"O","·--·":"P","--·-":"Q","·-·":"R","···":"S","-":"T","··-":"U","···-":"V","·--":"W","-··-":"X","-·--":"Y","--··":"Z",
  "-----":"0","·----":"1","··---":"2","···--":"3","····-":"4","·····":"5","-····":"6","--···":"7","---··":"8","----·":"9",
  "·-·-·-":".","--··--":",","··--··":"?","-····-":"-","-···-":"=","---···":":","·-·-·":"+","-··-·":"/",
  "-·--·":"(","-·--·-":")","··--·-":"_","---·":"!","-·-·--":"!",".-.-..":"\n","/":" "
};


var Found = {
  HIDDEN: {
    _name: "hidden",
    HOVER: { _name: "hover", weight: 0, category: "HIDDEN", detail: "Shown on image hover:" },
    NULL_ELM: { _name: "nullElm", weight: 1, category: "HIDDEN", detail: "Declared on hidden elements:" }
  },
  SUSPICIOUS: {
    _name: "suspicious",
    GIBBERISH: { _name: "gibberish", weight: 0, category: "SUSPICIOUS", detail: "Potentially useful text:" },
    LOCATION: { _name: "location", weight: -1, category: "SUSPICIOUS", detail: "Located under topic:" },
    OBSCURED: { _name: "obscured", weight: 1, category: "SUSPICIOUS", detail: "Potentially obscured link:" },
    SINGULAR: { _name: "singular", weight: 0, category: "SUSPICIOUS", detail: "Individually marked:", format: "$1 " }
  },
  DECODED: {
    _name: "decoded",
    ASCII: { _name: "decodedAscii", weight: 1, category: "DECODED", detail: "Decoded from ascii numbers:" },
    BASE64: { _name: "decodedBase64", weight: 2, category: "DECODED", detail: "Decoded from a base64 string:" },
    BINARY: { _name: "decodedBinary", weight: 2, category: "DECODED", detail: "Decoded from a binary sequence:" },
    GENETIC: { _name: "decodedGenetic", weight: 2, category: "DECODED", detail: "Decoded from a genetic sequence:" },
    HEX: { _name: "decodedHex", weight: 1, category: "DECODED", detail: "Decoded from a hex sequence:" },
    MORSE: { _name: "decodedMorse", weight: 1, category: "DECODED", detail: "Decoded from morse code sequence:" }
  },
  SEQUENCE: {
    _name: "sequence",
    BASE64: { _name: "base64", weight: 1, category: "SEQUENCE", detail: "Looks base64 encoded:" },
    DECIMAL: { _name: "decimal", weight: 0, category: "SEQUENCE", detail: "Looks like a decimal sequence:" },
    GENETIC: { _name: "genetic", weight: 0, category: "SEQUENCE", detail: "Looks like DNA code:" },
    GIFT: { _name: "gift", weight: 3, category: "SEQUENCE", detail: "Looks like a giveaway code:", format: "<a href='/giveaway/$1/' target='_blank'>$1</a><hr/>" },
    GIFT_LINK: { _name: "giftLink", weight: 3, category: "SEQUENCE", detail: "Giveaway links:", format: "<a href='$1' target='_blank'>$1</a><hr/>" },
    GIFT_PART: { _name: "giftPart", weight: 2, category: "SEQUENCE", detail: "Looks like a partial giveaway code:" },
    IMGUR: { _name: "imgur", weight: 1, category: "SEQUENCE", detail: "Looks like an Imgur image code:", format: "<a href='http://imgur.com/$1' target='_blank'>$1</a><hr/>" },
    LINK: { _name: "link", weight: 2, category: "SEQUENCE", detail: "Secret links:", format: "<a href='$1' target='_blank'>$1</a><hr/>" },
    MORSE: { _name: "morse", weight: 0, category: "SEQUENCE", detail: "Looks like morse code:" },
    EXTERNAL: { _name: "external", weight: 2, category: "SEQUENCE", detail: "Looks like a puzzle code (ITH/Jig):",
                format: "<div>$1 <span style='float:right;'>" +
                        "<a class='fa fa-question-circle-o' title='ItsTooHard' href='http://itstoohard.com/puzzle/$1' target='_blank'></a> / " +
                        "<a class='fa fa-puzzle-piece' title='Jigidi' href='https://www.jigidi.com/jigsaw-puzzle/$1' target='_blank'></a>" +
                        "</span></div> <div style='clear:both;'></div>" }
  }
};

var findings = {};

function addFinding(postId, sort, value) {
  var category = Found[sort.category]._name,
      type = sort._name;

  if (!findings[postId]) { findings[postId] = {}; }
  if (!findings[postId][category]) { findings[postId][category] = {}; }
  if (!findings[postId][category][type]) { findings[postId][category][type] = []; }

  var foundArr = findings[postId][category][type];

  if (Array.isArray(value)) {
    findings[postId][category][type] = foundArr.concat(value);
  } else {
    foundArr.push(value);
  }
}

// // // // //

/* Return altered strings */
var perform = {
  rotN: function(string, N) {
    return string.replace(/[A-Za-z]/g, function(c) {
      return String.fromCharCode((c<="Z"? 90:122) >= (c=c.charCodeAt(0)+N)? c:c-26);
    });
  },

  scriptDecode: function(string) {
    var encoded = string.split("-");
        encoded.shift();

    for(var i=0; i<encoded.length; i++) {
      encoded[i] = String.fromCharCode(parseInt(encoded[i], 16));
    }

    return perform.rotN(encoded.join(""), 13);
  }
};

/* Return boolean if match */
var checkIf = {
  nonsense: function(string) {
    var vowels = 1,
        consonants = 1,
        variety = "";

    if (string) {
      if (string.search(/\.com\b/) > -1) { return false; }

      for(var i = 0; i < string.length && variety.length < 21; i++) {
        var character = string.charAt(i).toLowerCase();

        if ((/[aeiou]/).test(character)) {
          vowels++;
        } else if ((/[bcdfghjklmnpqrstvwxyz]/).test(character)) {
          consonants++;
          if(variety.indexOf(character) == -1) {
            variety += character;
          }
        }
      }

      var ratio = vowels / (consonants + vowels);
      var diversity = variety.length / consonants;

      return ((ratio < 0.2 || ratio > 0.6) || (variety.length > 1 && diversity < 0.30) || string.match(/[a-z]*?\d+[a-z]*?/i));
    }

    return false;
  },

  usable: function(string) {
    return !!(string.match(/^[\w,.!?: \/]+$/));
  },

  falseB64: function(string) {
    //catch false positives - normal words that just happen to decode properly
    var catches = ["Unlucky"];

    return (catches.indexOf(string) > -1);
  },

  _measure: document.createElement("canvas").getContext("2d"),
  small: function(string) {
    return checkIf.singular(string) && checkIf._measure.measureText(string).width < 6;
  },

  singular: function(string) {
    return string.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, "_").length == 1;
  },

  newSet: function($doc, postId) {
    return !((postId !== "undefined" && !$doc.find("[id='"+ postId +"']").length)
              || (postId === "undefined" && !$doc.find("header").length)); //special case for root post
  }
}

/* Check for and record if match */
var lookFor = {
  topic: function() {
    var topic = $(".sidebar__navigation__item.is-selected").text().trim();
    if (topic === "Puzzles") { addFinding(undefined, Found.SUSPICIOUS.LOCATION, topic); }
  },

  anchor: function(postId, $elm) {
    if ($elm.length && $elm.is("a")) {
      var href = $elm.attr("href");

      if (!$elm.html() || checkIf.small($elm.text())) {
        if (href) { addFinding(postId, Found.HIDDEN.NULL_ELM, href); }
      } else {
        //not a hidden link, but check if it's location is useful
        lookFor.length(postId, href);
      }
    }
  },

  formatted: function(postId, $elm) {
    if ($elm.is("strong") || $elm.is("em") || $elm.is("code") || $elm.hasClass("spoiler")) {
      lookFor.singles(postId, $elm.text());
    }
  },

  imageText: function(postId, $elm) {
    if ($elm.length && $elm.is("img")) {
      var title = $elm.attr("title");
      if (title) {
        addFinding(postId, Found.HIDDEN.HOVER, title);
        lookFor.gibberish(postId, title);
      }
    }
  },

  singles: function(postId, string) {
    if (!string) { return; }

    //single letters
    if (checkIf.singular(string) && string.match(/[A-Za-z0-9]/)) {
      addFinding(postId, Found.SUSPICIOUS.SINGULAR, string);
    }
  },

  combiningSingular: function(postId, string) {
    if (!string) { return; }

    var combining = string.replace(/\u1F600-\u1F64F/g, "").match(/[\u0000-\u007F](?=[\u0300-\u036F\u1AB0-\u1AFF\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F])/g);
    if (combining && combining.join("").trim().length) {
      addFinding(postId, Found.SUSPICIOUS.SINGULAR, combining);
    }
  },

  obscured: function(postId, string) {
    if (!string) { return; }

    var seq = string.match(/\b\w{5}:\/\/.+?(\s|$)/g);
    if (seq) {
      for(var i=0; i<seq.length; i++) {
        if (seq[i].toLowerCase().indexOf("http") === -1) {
          addFinding(postId, Found.SUSPICIOUS.OBSCURED, seq[i]);
        }
      }
    }
  },

  gibberish: function(postId, string) {
    if (!string) { return; }

    var seq = string.match(/(^|\s)\w{5,8}(\s|$)/g);
    if (seq) {
      for(var i=0; i<seq.length; i++) {
        var at = seq[i].trim();
        if (at.length != 6 && checkIf.nonsense(at) && !at.match(/^\d+$/)) {
          addFinding(postId, Found.SUSPICIOUS.GIBBERISH, at);
        }
      }
    }
  },

  morse: function(postId, string) {
    if (!string) { return; }

    var seq = string.match(/[\s\\\/.·*_−-]*[.·*_−-]{3,}[\s\\\/.·*_-]*/g);
    if (seq) {
      for(var i=0; i<seq.length; i++) {
        var at = seq[i].replace(/[.·*]/g, "·").replace(/[_−-]/g, "-").replace(/\r?\n/g, "").trim();
        if (!at.match(/^·+$/) && !at.match(/^-+$/) && at !== '·-·' && at !== '-·-') {
          addFinding(postId, Found.SEQUENCE.MORSE, at);

          //try to decode
          var letters = at.split(/\s+/g),
              decode = "";

          for(var l=0; l<letters.length; l++) {
            if (MORSE_MAP[letters[l]]) { decode += MORSE_MAP[letters[l]]; }
          }

          if (decode && decode.length > 3) {
            addFinding(postId, Found.DECODED.MORSE, decode);
          }
        }
      }
    }
  },

  genetic: function(postId, string) {
    if (!string) { return; }

    var seq = string.match(/(\b[GUAC]{3}(\s+|$))+/g);
    if (seq) { addFinding(postId, Found.SEQUENCE.GENETIC, seq); }
  },

  binary: function(postId, string) {
    if (!string) { return; }

    var seq = string.match(/([01\s]{8,})+/g);
    if (seq) {
      var each = seq.join("").replace(/\s+/g, "").match(/([01]{8})/g);
      var decode = "";

      if (!each) { return; }
      for(var i = 0; i<each.length; i++) {
        if (each[i]) { decode += String.fromCharCode(parseInt(each[i], 2)); }
      }

      if (decode) {
        addFinding(postId, Found.DECODED.BINARY, decode);
      }
    }
  },
  
  hex: function(postId, string) {
    if (!string) { return; }
    
    var seq = string.toUpperCase().match(/([0-9A-F\s]{8,})+/g);
    if (seq) {
      var each = seq.join("").replace(/\s+/g, "").match(/([0-9A-F]{2})/g);
      var decode = "";

      if (!each) { return; }
      for(var i = 0; i<each.length; i++) {
        if (each[i]) { decode += String.fromCharCode(parseInt(each[i], 16)); }
      }

      if (decode && checkIf.usable(decode)) {
        addFinding(postId, Found.DECODED.HEX, decode);
      }
    }
  },
  
  ascii: function(postId, string) {
    if (!string) { return; }
    
    var seq = string.toUpperCase().match(/([0-9\s]{8,})+/g);
    if (seq) {
      var each = seq.join("").match(/([0-9]{2,3}\s?)/g);
      var decode = "";

      if (!each) { return; }
      for(var i = 0; i<each.length; i++) {
        if (each[i]) { decode += String.fromCharCode(parseInt(each[i], 10)); }
      }

      if (decode && checkIf.usable(decode)) {
        addFinding(postId, Found.DECODED.ASCII, decode);
      }
    }
  },

  decimal: function(postId, string) {
    if (!string) { return; }

    var seq = string.match(/(\b[\dA-Fa-f]+\b(\s+|$)){3,}/g);
    if (seq) {
      addFinding(postId, Found.SEQUENCE.DECIMAL, seq);
      
      lookFor.hex(postId, string);
      lookFor.ascii(postId, string);
    }
  },

  base64: function(postId, string) {
    if (!string) { return; }

    var seq = string.match(/\b[A-Za-z0-9+\/]{5,}=*\b/g);
    if (seq) {
      for(var i=0; i<seq.length; i++) {
        try {
          var decode = atob(seq[i]);
          if (checkIf.usable(decode) && !checkIf.falseB64(seq[i])) {
            addFinding(postId, Found.SEQUENCE.BASE64, seq[i]);
            addFinding(postId, Found.DECODED.BASE64, decode);
          }
        } catch(ignore) {}
      }
    }
  },

  link: function(postId, string) {
    if (!string) { return; }

    testString = string.toLowerCase();
    if (testString.search(/giveaway\/\w{5}\//) > -1 || testString.search(/giveaways\/\w{8}-/) > -1) {
      addFinding(postId, Found.SEQUENCE.GIFT_LINK, string);
    } else if (testString.indexOf("http") === 0 && testString.length > 8) {
      addFinding(postId, Found.SEQUENCE.LINK, string);
    }
  },

  length: function(postId, string) {
    if (!string || string.length < 5 || !string.match(/^[\w+?-]+$/)) { return; }

    if (string.length == 5) {
      if (string.match(/^[A-Za-z0-9]+$/g)) {
        addFinding(postId, Found.SEQUENCE.GIFT, string);
      } else {
        addFinding(postId, Found.SEQUENCE.GIFT_PART, string);
      }
    } else if (string.length == 7) {
      addFinding(postId, Found.SEQUENCE.IMGUR, string);
    } else if (string.length == 8) {
      addFinding(postId, Found.SEQUENCE.EXTERNAL, string);
    }

    if (string.indexOf("ESGST") == 0) {
      addFinding(postId, Found.SEQUENCE.GIFT, perform.scriptDecode(string));
    }
  },

  lengthMod: function(postId, string) {
    if (!string || string.length < 5 || !string.match(/^[\w+?-]+$/)) { return; }

    var sequence = [];
    if (string.length % 5 == 0) {
      sequence = string.match(/.{5}/g);
    } else if (string.length % 7 == 0) {
      sequence = string.match(/.{7}/g);
    } else if (string.length % 8 == 0) {
      sequence = string.match(/.{8}/g);
    }

    for(var i=0; i<sequence.length; i++) {
      lookFor.length(postId, sequence[i]);
    }
  }
};

/* Pull text and test */
var actOn = {
  tags: function(postId, $parent) {
    $.each($parent.children(), function (idx, child) {
      try {
        var $child = $(child),
        cText = $child.text();

        //go straight to children for these tags
        if ($child.is("ul") || $child.is("ol") || $child.is("pre") || $child.is("blockquote")) {
          actOn.tags(postId, $child);
          return;
        }

        // search for something interesting
        lookFor.anchor(postId, $child);
        lookFor.imageText(postId, $child);
        lookFor.formatted(postId, $child);
        lookFor.obscured(postId, cText);
        lookFor.morse(postId, cText);
        lookFor.genetic(postId, cText);
        lookFor.binary(postId, cText);
        lookFor.decimal(postId, cText);
        lookFor.base64(postId, cText);

        //continue on to children
        actOn.tags(postId, $child);
      } catch(e) { console.error(e); }
    });
  },

  page: function($doc) {
    $.each($doc.find(".markdown"), function(idx, sniff) {
      try {
        var $sniff = $(sniff),
            postId = $sniff.parents(".comment__summary").attr("id");

        actOn.tags(postId, $sniff);
        lookFor.combiningSingular(postId, $sniff.text());
      } catch(e) { console.error(e); }
    });

    //check for possible sequences
    for(var postId in findings) {
      //if not in current doc, we've already ran this check
      if (!checkIf.newSet($doc, postId)) { continue; }

      if (findings.hasOwnProperty(postId)) {
        var findId = findings[postId];

        for(var category in findId) {
          if (category === Found.SEQUENCE._name) { continue; }

          if (findId.hasOwnProperty(category)) {
            var findCat = findId[category];

            for(var type in findCat) {
              if (type === Found.SUSPICIOUS.LOCATION._name) { continue; }

              if (findCat.hasOwnProperty(type)) {
                var findType = findCat[type];

                //group these up to check
                if (type === Found.SUSPICIOUS.SINGULAR._name) {
                  var joint = findType.join("");

                  lookFor.lengthMod(postId, joint);
                  lookFor.link(postId, joint);
                }

                //keep these separate to check
                for(var i=0; i<findType.length; i++) {
                  if (type !== Found.HIDDEN.HOVER._name) {
                    lookFor.length(postId, findType[i]);
                  }

                  lookFor.link(postId, findType[i]);
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
    } catch(e) { console.error(e); }
  }
};

var visualize = {
  style: function() {
    GM_addStyle("div.comment__secrets{ display: inline-block; cursor: pointer; margin-right: 6px; }" +
                ".suspicion_none{ color: #DDD; }" +
                ".suspicion_low { color: #BBB; }" +
                ".suspicion_med { color: #777; }" +
                ".suspicion_high{ color: #111; }" +
                ".suspicion__content{ background-color: #222; border: 1px solid #2D291F; border-radius: 4px; box-shadow: 4px 4px 7px #555; "+
                "                     display: none; position: absolute; max-width: 256px; padding: 5px; color: #B9A98F; word-wrap: break-word; }" +
                ".suspicion__content hr:not(.split){ border: 1px solid #333; border-top: none; margin: 0.15em; }" +
                ".suspicion__content div > hr:not(.split):last-of-type{ display: none; }" +
                ".suspicion__content .fa{ color: #FFF; }" +
                ".suspicion__results__inner-wrap > div:not(:first-of-type){ margin-top: 0.5em; }" +
                ".suspicion__content strong{ color: #EDEBE5; }" +
                ".suspicion__content a, .suspicion__content a.fa{ color: #B99964; }" +
                ".suspicion__content a:hover, .suspicion__content a.fa:hover{ color: #B9780F; }" +
                ".suspicion__content a.local{ color: #B96464; }" +
                ".suspicion__content a.local:hover{ color: #B90F0F; }");

    //color compatibility with dark theme
    if ($("body").css("background-color") !== "rgb(149, 164, 192)") {
      console.log("Assuming dark theme and adjusting colors");
      GM_addStyle(".suspicion_none{ color: #2E2E2C; }" +
                  ".suspicion_low { color: #5C5C58; }" +
                  ".suspicion_med { color: #B8B8B0; }" +
                  ".suspicion_high{ color: #FFFFFF; }" +
                  ".suspicion__content{ background-color: #f0f2f5; border: 1px solid #D2D6E0; color: #465670; }" +
                  ".suspicion__content hr:not(.split){ border-color: #d0d2d5; }" +
                  ".suspicion__content .fa{ color: #000; }" +
                  ".suspicion__content strong{ color: #12141A; }" +
                  ".suspicion__content a, .suspicion__content a.fa{ color: #4B72D4; }" +
                  ".suspicion__content a:hover, .suspicion__content a.fa:hover{ color: #8A9FD4; }" +
                  ".suspicion__content a.local{ color: #AF4AD4; }" +
                  ".suspicion__content a.local:hover{ color: #DAA6ED; }");
    }
  },

  _box: $("<div/>").addClass("suspicion__content")
                   .html("<em class='fa fa-user-secret'></em><div class='suspicion__results__outer-wrap'></div>")
                   .on('mouseleave', function() { $(this).css({"display": "none"}).find(".suspicion__results__outer-wrap").html(""); })
                   .appendTo($("body")),

  reveal: function(elm, display) {
    var $elm = $(elm),
        offset = $elm.offset(),
        pad = 6;

    var $content = $("<div/>").addClass("suspicion__results__inner-wrap");
    for(var i=0; i<display.primary.length; i++) {
      var data = display.primary[i];
      $content.append("<div><strong>"+ data.title +"</strong><br/>"+ data.content +"</div>");
    }

    if (display.secondary.length) {
      var $more = $("<a/>").addClass("local").attr("href", "#").html("Show All Clues")
                          .on("click", function(evt) {
                            for(var i=0; i<display.secondary.length; i++) {
                              var data = display.secondary[i];
                              $content.append("<div><strong>"+ data.title +"</strong><p>"+ data.content +"</p></div>");
                            }

                            $(this).hide();
                            evt.preventDefault();
                          });

      $content.append("<hr class='split' />").append($more);
    }

    visualize._box.css({"display": "block", "top": Math.floor(offset.top - pad), "left": Math.floor(offset.left - pad)})
                  .find(".suspicion__results__outer-wrap").html($content);
  },

  icon: function($doc) {
    //inject icon on scanned comments
    for(var postId in findings) {
      //if not in current doc, we've already added this
      if (!checkIf.newSet($doc, postId)) { continue; }

      if (findings.hasOwnProperty(postId)) {
        (function(_postId) {
          //build display text from findings
          var highest = -1,
              display = { primary: [], secondary: [], raw: [] };

          for(var category in Found) {
            if (Found.hasOwnProperty(category) && findings[_postId].hasOwnProperty(Found[category]._name)) {
              var findCat = Found[category];

              for(var type in findCat) {
                if (type === "_name") { continue; }

                if (findCat.hasOwnProperty(type) && findings[_postId][findCat._name].hasOwnProperty(findCat[type]._name)) {
                  var findType = findCat[type],
                      format = findType.format || "$1<hr/>",
                      content = "";

                  if (highest < findType.weight) {
                    highest = findType.weight;
                  }

                  for(var i=0; i<findings[_postId][findCat._name][findType._name].length; i++) {
                    content += format.replace(/\$1/g, findings[_postId][findCat._name][findType._name][i]);
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

          for(var i=0; i<display.raw.length; i++) {
            if (display.raw[i].weighs == highest) {
              display.primary.push(display.raw[i]);
            } else {
              display.secondary.push(display.raw[i]);
            }
          }

          var byWeight = function(a, b) { return b.weighs - a.weighs; };
          display.primary.sort(byWeight);
          display.secondary.sort(byWeight);

          //make icon and append to post
          if (highest < 0) { highest = 0; }
          var $secret = $("<div/>").addClass("comment__secrets").addClass(BELIEFS[highest].style)
                                   .html("<em class='fa fa-user-secret' title='"+ BELIEFS[highest].wording +"'></em>")
                                   .on('click', function() { visualize.reveal(this, display); });

          if (_postId === "undefined") {
            var $base = $doc.find(".page__description__display-state");
            if ($base.length == 0) {
              $doc.find(".comment").first().find(".comment__actions").prepend($secret);
            } else {
              var $alt = $(".page__description__edit");
              if ($alt.length > 0) {
                $alt.before($secret);
              } else {
                $base.append($secret);
              }
            }
          } else {
            $doc.find("[id='"+ _postId +"']").find(".comment__actions").prepend($secret);
          }
        })(postId);
      }
    }
  }
};

// // // // //

//one-time calls
visualize.style();
lookFor.topic();

//sniffer calls
var $document = $(document),
    originalContent = $(".comment");

$document.on('scroll', function() {
  var currentContent = $(".comment");
  if (currentContent.length > originalContent.length) {
    actOn.content($(currentContent).not(originalContent));
    originalContent = currentContent;
  }
});

actOn.content($document); //inital page load
